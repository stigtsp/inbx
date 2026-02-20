use v5.36;

use Digest::SHA qw(sha256_hex);
use File::Temp qw(tempdir);
use MIME::Base64 qw(encode_base64);
use Mojo::JSON qw(decode_json);
use Mojo::Parameters;
use Mojo::Server;
use Mojo::Transaction::HTTP;
use Test::More;

my $tmp = tempdir(CLEANUP => 1);

local $ENV{INBX_STORAGE_PATH} = $tmp;
local $ENV{INBX_MAX_ENTRIES}  = 3;
local $ENV{INBX_USER}         = 'viewer';
local $ENV{INBX_PASS}         = 'secret-pass';
local $ENV{MOJO_LISTEN}       = '';
delete $ENV{INBX_POST_TOKEN};

my $app  = Mojo::Server->new->load_app('./inbx.pl');
my $auth = 'Basic ' . encode_base64('viewer:secret-pass', '');

sub req ($method, $path, $headers = {}, $body = '') {
  my $tx = Mojo::Transaction::HTTP->new;
  $tx->req->method($method);
  $tx->req->url->parse($path);
  $tx->req->headers->from_hash($headers);
  if (length $body) {
    $tx->req->body($body);
    $tx->req->headers->content_length(length $body)
      unless defined $tx->req->headers->content_length;
  }
  $app->handler($tx);
  return $tx;
}

my $tx = req('GET', '/inbx');
is($tx->res->code, 200, 'GET /inbx ok');
like($tx->res->body, qr/X-Inbx-Token/, '/inbx advertises token header when set');

ok(-f "$tmp/.post_token", 'post token file created on startup');
open my $tfh, '<:raw', "$tmp/.post_token" or die "open token file: $!";
chomp(my $token = <$tfh> // '');
close $tfh;
ok(length $token, 'generated token is non-empty');

$tx = req('POST', '/inbx', {'Content-Type' => 'text/plain'}, "hello without token\n");
is($tx->res->code, 401, 'POST /inbx without token rejected');
like($tx->res->body, qr/invalid X-Inbx-Token/, 'missing token message shown');

$tx = req('POST', '/inbx', {'X-Inbx-Token' => 'wrong', 'Content-Type' => 'text/plain'}, "hello wrong token\n");
is($tx->res->code, 401, 'POST /inbx with wrong token rejected');

my $first_body = "first entry\n";
$tx = req(
  'POST', '/inbx',
  {
    'X-Inbx-Token'  => $token,
    'X-Test-Header' => 'alpha',
    'X-Forwarded-For' => '198.51.100.7',
    'Content-Type'  => 'text/plain',
  },
  $first_body,
);
is($tx->res->code, 201, 'POST /inbx with valid token stored');
is($tx->res->body, "Stored\n", 'store response body');

my @initial_entries = grep { -f $_ } glob "$tmp/*.txt";
is(scalar @initial_entries, 1, 'one stored entry file after first post');
my $entry_file = $initial_entries[0];
my $meta_file  = "$entry_file.meta.json";
ok(-f $meta_file, 'json metadata companion file exists');

open my $mfh, '<:raw', $meta_file or die "open metadata file: $!";
my $meta_raw = do { local $/; <$mfh> // '' };
close $mfh;

my $meta = decode_json($meta_raw);
is($meta->{sha256}, sha256_hex($first_body), 'metadata has sha256 of submission body');
like($meta->{timestamp_utc}, qr/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'metadata has UTC timestamp');
is($meta->{ip}, '198.51.100.7', 'metadata uses submitter IP');
ok(ref $meta->{headers} eq 'HASH', 'metadata has headers object');

my %headers_lc = map { lc($_) => $meta->{headers}{$_} } keys %{ $meta->{headers} };
my $x_test = $headers_lc{'x-test-header'};
ok(defined $x_test, 'metadata includes custom request header');
if (ref $x_test eq 'ARRAY') {
  ok((grep { defined $_ && $_ eq 'alpha' } @$x_test) > 0, 'custom header value recorded');
} else {
  is($x_test, 'alpha', 'custom header value recorded');
}

$tx = req('GET', '/inbx/view');
is($tx->res->code, 401, 'GET /inbx/view requires auth');

$tx = req('GET', '/inbx/view', {Authorization => $auth});
is($tx->res->code, 200, 'GET /inbx/view with auth works');
like($tx->res->body, qr/first entry/, 'view includes stored entry');
like($tx->res->body, qr/\Q$token\E/, 'view includes current token');
like($tx->res->body, qr/X-Inbx-Token: \Q$token\E/, 'view includes tokenized curl example');

$tx = req('POST', '/inbx/token/unset', {Authorization => $auth, 'Content-Type' => 'application/x-www-form-urlencoded'}, '');
is($tx->res->code, 403, 'token unset without CSRF is rejected');
like($tx->res->body, qr/Bad CSRF token/, 'csrf rejection message');

$tx = req('GET', '/inbx/view', {Authorization => $auth});
is($tx->res->code, 200, 'GET view for csrf token works');
my $view_body = $tx->res->body;
$view_body =~ /name="csrf_token"[^>]*value="([^"]+)"/
  or die 'csrf token not found in view';
my $csrf = $1;
ok(defined $csrf && length $csrf, 'csrf token value extracted from html');

my $set_cookie = $tx->res->headers->header('Set-Cookie') // '';
my ($cookie_header) = $set_cookie =~ /^([^;]+)/;
ok(defined $cookie_header && length $cookie_header, 'session cookie present');

my $form = Mojo::Parameters->new(csrf_token => $csrf)->to_string;
$tx = req(
  'POST', '/inbx/token/unset',
  {
    Authorization => $auth,
    Cookie        => $cookie_header,
    'Content-Type' => 'application/x-www-form-urlencoded',
  },
  $form,
);
is($tx->res->code, 302, 'token unset with valid CSRF redirects');
like($tx->res->headers->location // '', qr{/inbx/view}, 'unset redirects to /inbx/view');

ok(!-e "$tmp/.post_token", 'post token file removed after unset');

$tx = req('GET', '/inbx');
is($tx->res->code, 200, 'GET /inbx still works');
unlike($tx->res->body, qr/X-Inbx-Token/, '/inbx no longer requires token once unset');

# Submission endpoint intentionally does not use CSRF so curl uploads work.
for my $n (1 .. 5) {
  $tx = req('POST', '/inbx', {'Content-Type' => 'text/plain'}, "entry $n\n");
  is($tx->res->code, 201, "tokenless POST works after unset ($n)");
}

my @entries = grep { -f $_ } glob "$tmp/*.txt";
is(scalar @entries, 3, 'retention trimming keeps only newest entries');

my @meta_files = grep { -f $_ } glob "$tmp/*.txt.meta.json";
is(scalar @meta_files, 3, 'retention trimming keeps companion metadata in sync');

$tx = req('GET', '/inbx/view', {Authorization => $auth});
is($tx->res->code, 200, 'view still works after token unset');
like($tx->res->body, qr/\(unset\)/, 'view shows token unset state');
like($tx->res->body, qr/curl -sS -X POST --data-binary \@\/tmp\/some-info/, 'view curl example switches to tokenless form');
unlike($tx->res->body, qr/X-Inbx-Token:/, 'view curl example omits token header when unset');

done_testing;
