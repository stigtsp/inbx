#!/usr/bin/env perl
use v5.36;

use Mojolicious::Lite -signatures;
use Crypt::PBKDF2;
use Digest::SHA qw(sha256_hex);
use File::Path qw(make_path);
use MIME::Base64 qw(decode_base64);
use Mojo::JSON qw(encode_json decode_json);
use Mojo::Util qw(steady_time);
use POSIX qw(strftime);

my $storage_dir = $ENV{INBX_STORAGE_PATH} || '/tmp/inbx';
my $max_entries = $ENV{INBX_MAX_ENTRIES}  || 100;
my $auth_user   = $ENV{INBX_USER}         || 'inbx';
my $auth_pass_hash = '';
my $entry_name_re = qr/^\d{8}-\d{6}-\d+-\d+\.txt$/;

die "INBX_STORAGE_PATH must not be '/'\n" if $storage_dir eq '/';

app->max_request_size(1_048_576);
app->secrets([$ENV{INBX_SECRET} || 'inbx-dev-secret']);

make_path($storage_dir) unless -d $storage_dir;

my $token_file     = "$storage_dir/.post_token";
my $auth_meta_file = "$storage_dir/.view_auth.meta.json";
my $pbkdf2         = Crypt::PBKDF2->new(
  hash_class => 'HMACSHA2',
  hash_args  => {sha_size => 256},
  iterations => 120_000,
  salt_len   => 16,
);

sub random_token {
  my $bytes = '';
  if (open my $rfh, '<:raw', '/dev/urandom') {
    read $rfh, $bytes, 24;
    close $rfh;
  }

  my $missing = 24 - length $bytes;
  if ($missing > 0) {
    $bytes .= join '', map { chr(int rand 256) } 1 .. $missing;
  }

  return unpack('H*', $bytes);
}

sub write_token ($token) {
  if (length $token) {
    return 0 unless open my $fh, '>:raw', $token_file;
    print {$fh} $token;
    close $fh;
    return 1;
  }

  unlink $token_file if -e $token_file;
  return 1;
}

sub read_token {
  return '' unless -f $token_file;
  return '' unless open my $fh, '<:raw', $token_file;
  my $token = <$fh> // '';
  close $fh;
  chomp $token;
  return $token;
}

sub write_auth_meta ($meta) {
  return 0 unless open my $fh, '>:raw', $auth_meta_file;
  print {$fh} encode_json($meta) . "\n";
  close $fh;
  chmod 0600, $auth_meta_file;
  return 1;
}

sub read_auth_meta {
  return undef unless -f $auth_meta_file;
  return undef unless open my $fh, '<:raw', $auth_meta_file;
  my $raw = do { local $/; <$fh> // '' };
  close $fh;
  my $meta = eval { decode_json($raw) };
  return undef unless ref $meta eq 'HASH';
  return $meta;
}

sub submitter_ip ($c) {
  my $xff = $c->req->headers->header('X-Forwarded-For') // '';
  if (length $xff) {
    my ($first) = split /\s*,\s*/, $xff;
    return $first if defined $first && length $first;
  }
  return $c->tx->remote_address // '';
}

sub request_headers_hash ($c) {
  my %headers = %{ $c->req->headers->to_hash(1) };
  return \%headers;
}

my $post_token;
if (exists $ENV{INBX_POST_TOKEN}) {
  $post_token = $ENV{INBX_POST_TOKEN} // '';
  write_token($post_token);
} else {
  $post_token = read_token();
  if (!length $post_token) {
    $post_token = random_token();
    write_token($post_token);
  }
}

if (defined($ENV{INBX_PASS}) && length($ENV{INBX_PASS})) {
  $auth_pass_hash = $pbkdf2->generate($ENV{INBX_PASS});
} else {
  my $meta = read_auth_meta();
  if ($meta && ($meta->{user} // '') eq $auth_user && length($meta->{pass_hash} // '')) {
    $auth_pass_hash = $meta->{pass_hash};
  } else {
    my $generated_pass = random_token();
    $auth_pass_hash = $pbkdf2->generate($generated_pass);
    my $meta_out = {
      user         => $auth_user,
      pass_hash    => $auth_pass_hash,
      hash_scheme  => 'PBKDF2-HMAC-SHA256',
      generated_at => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
    };
    die "Failed to persist generated viewer password hash\n"
      unless write_auth_meta($meta_out);
    app->log->warn("INBX_PASS was not set. Generated viewer password for '$auth_user': $generated_pass");
  }
}

helper is_authed => sub ($c) {
  my $header = $c->req->headers->authorization // '';
  return 0 unless $header =~ /^Basic\s+(.+)$/i;

  my $decoded = eval { decode_base64($1) } // '';
  return 0 unless defined $decoded && length $decoded;

  my ($user, $pass) = split /:/, $decoded, 2;
  return 0 unless defined $user && defined $pass;
  return 0 unless $user eq $auth_user;
  my $ok = eval { $pbkdf2->validate($auth_pass_hash, $pass) } // 0;
  return $ok ? 1 : 0;
};

helper require_auth => sub ($c, $realm = 'inbx') {
  return 1 if $c->is_authed;
  $c->res->headers->www_authenticate(qq{Basic realm="$realm"});
  $c->render(text => "Authentication required\n", status => 401);
  return 0;
};

helper post_token => sub ($c) { return $post_token };

helper set_post_token => sub ($c, $token) {
  $token //= '';
  if (!write_token($token)) {
    return 0;
  }
  $post_token = $token;
  return 1;
};

helper list_entries => sub ($c) {
  opendir(my $dh, $storage_dir) or return [];
  my @entries = grep { /$entry_name_re/ && -f "$storage_dir/$_" } readdir($dh);
  closedir $dh;

  @entries = sort {
    (stat("$storage_dir/$b"))[9] <=> (stat("$storage_dir/$a"))[9]
  } @entries;
  return \@entries;
};

helper trim_entries => sub ($c) {
  my $entries = $c->list_entries;
  return if @$entries <= $max_entries;

  for my $old (@$entries[$max_entries .. $#$entries]) {
    next unless $old =~ /$entry_name_re/;
    unlink "$storage_dir/$old";
    unlink "$storage_dir/$old.meta.json";
    unlink "$storage_dir/$old.meta";
  }
};

get '/inbx' => sub ($c) {
  my $token = $c->post_token;
  my $msg   = length($token)
    ? "POST plain text to /inbx (max 1MB) with X-Inbx-Token or Basic Auth. View at /inbx/view.\n"
    : "POST plain text to /inbx (max 1MB). Basic Auth is also accepted. View at /inbx/view.\n";

  $c->render(
    text => $msg
  );
};

post '/inbx' => sub ($c) {
  my $token = $c->post_token;
  my $token_ok = 0;
  my $basic_token_ok = 0;
  if (length $token) {
    my $got = $c->req->headers->header('X-Inbx-Token') // '';
    $token_ok = (length($got) && $got eq $token) ? 1 : 0;

    my $auth = $c->req->headers->authorization // '';
    if ($auth =~ /^Basic\s+(.+)$/i) {
      my $decoded = eval { decode_base64($1) } // '';
      if (defined $decoded && length $decoded) {
        my ($user, $pass) = split /:/, $decoded, 2;
        $user //= '';
        $pass //= '';
        $basic_token_ok = (($user eq $token) || ($pass eq $token)) ? 1 : 0;
      }
    }
  }

  if (length($token) && !$token_ok && !$basic_token_ok) {
    return $c->render(
      text   => "Missing or invalid X-Inbx-Token (or use Basic Auth with token)\n",
      status => 401,
    );
  }

  my $body = $c->req->body // '';
  if (!length $body) {
    return $c->render(text => "Empty body\n", status => 400);
  }

  my $ts     = strftime('%Y%m%d-%H%M%S', gmtime);
  my $suffix = int(steady_time * 1_000_000) . "-" . int(rand(1_000_000));
  my $file   = "$storage_dir/$ts-$suffix.txt";
  my $meta_file = "$file.meta.json";

  my $fh;
  if (!open $fh, '>:raw', $file) {
    return $c->render(text => "Failed to write entry\n", status => 500);
  }
  print {$fh} $body;
  close $fh;

  my $metadata = encode_json({
    ip            => submitter_ip($c),
    timestamp_utc => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
    sha256        => sha256_hex($body),
    headers       => request_headers_hash($c),
  }) . "\n";

  my $mfh;
  if (!open $mfh, '>:raw', $meta_file) {
    unlink $file;
    return $c->render(text => "Failed to write metadata\n", status => 500);
  }
  print {$mfh} $metadata;
  close $mfh;

  $c->trim_entries;
  $c->render(text => "Stored\n", status => 201);
};

post '/inbx/token/generate' => sub ($c) {
  return unless $c->require_auth('inbx-view');
  my $v = $c->validation;
  $v->csrf_protect;
  return $c->render(text => "Bad CSRF token\n", status => 403)
    if $v->has_error('csrf_token');

  my $token = random_token();
  return $c->render(text => "Failed to set token\n", status => 500)
    unless $c->set_post_token($token);

  $c->redirect_to('/inbx/view');
};

post '/inbx/token/unset' => sub ($c) {
  return unless $c->require_auth('inbx-view');
  my $v = $c->validation;
  $v->csrf_protect;
  return $c->render(text => "Bad CSRF token\n", status => 403)
    if $v->has_error('csrf_token');

  return $c->render(text => "Failed to unset token\n", status => 500)
    unless $c->set_post_token('');

  $c->redirect_to('/inbx/view');
};

get '/inbx/view' => sub ($c) {
  return unless $c->require_auth('inbx-view');

  my $token = $c->post_token;
  my $host = $c->req->headers->header('X-Forwarded-Host')
    // $c->req->headers->host
    // 'localhost';
  my $proto = $c->req->headers->header('X-Forwarded-Proto')
    // $c->req->url->base->scheme
    // 'http';
  my $post_url = "$proto://$host" . $c->url_for('/inbx')->to_string;
  my $curl_cmd = length($token)
    ? qq{curl -sS -X POST -H "X-Inbx-Token: $token" --data-binary @/tmp/some-info "$post_url"}
    : qq{curl -sS -X POST --data-binary @/tmp/some-info "$post_url"};
  my $curl_cmd_basic = length($token)
    ? qq{curl -sS -u "inbx:$token" -X POST --data-binary @/tmp/some-info "$post_url"}
    : '';

  my $entries = $c->list_entries;
  my @items;
  for my $name (@$entries) {
    my $path = "$storage_dir/$name";
    my $fh;
    next unless open $fh, '<:raw', $path;
    local $/;
    my $body = <$fh>;
    close $fh;

    push @items, {
      name => $name,
      body => $body // '',
      mtime => scalar gmtime((stat($path))[9] || time) . ' UTC',
    };
  }

  my $html = <<'HTML';
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>inbx view</title>
  <style>
    body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin: 1.5rem; }
    h1 { font-size: 1.2rem; }
    .meta { color: #555; margin: 0.2rem 0 0.4rem 0; }
    pre { white-space: pre-wrap; border: 1px solid #ddd; padding: 0.8rem; background: #fafafa; }
    .controls { margin: 1rem 0; }
    .token { font-weight: bold; }
    .inline { display: inline-block; margin-right: 0.4rem; }
    button { font-family: inherit; }
    code { display: block; border: 1px solid #ddd; background: #f3f3f3; padding: 0.7rem; }
  </style>
</head>
<body>
  <h1>inbx submissions</h1>
  <div class="controls">
    <div>
      Post token:
      % if (length $token) {
      <span class="token"><%= $token %></span>
      % } else {
      <span class="token">(unset)</span>
      % }
    </div>
    <div style="margin:0.6rem 0 0.6rem 0">
      <form class="inline" method="post" action="/inbx/token/generate">
        <%= csrf_field %>
        <button type="submit">Generate New Token</button>
      </form>
      <form class="inline" method="post" action="/inbx/token/unset">
        <%= csrf_field %>
        <button type="submit">Unset Token</button>
      </form>
    </div>
    <div>Example curl:</div>
    <code><%= $curl_cmd %></code>
    % if (length $curl_cmd_basic) {
    <div style="margin-top:0.4rem">Basic Auth alternative (token as credential):</div>
    <code><%= $curl_cmd_basic %></code>
    % }
  </div>
  % for my $item (@$items) {
    <div class="meta"><%= $item->{name} %> | <%= $item->{mtime} %></div>
    <pre><%= $item->{body} %></pre>
  % }
</body>
</html>
HTML

  $c->render(
    inline => $html,
    items  => \@items,
    token  => $token,
    curl_cmd => $curl_cmd,
    curl_cmd_basic => $curl_cmd_basic,
  );
};

app->start;
