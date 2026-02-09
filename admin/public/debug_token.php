<?php
header('Content-Type: application/json');

$headers = [];
foreach ($_SERVER as $name => $value) {
    if (substr($name, 0, 5) == 'HTTP_') {
        $headers[$name] = $value;
    }
}

if (function_exists('apache_request_headers')) {
    $apache_headers = apache_request_headers();
} else {
    $apache_headers = 'Function not available';
}

echo json_encode([
    'SERVER_VARS' => $headers,
    'APACHE_HEADERS' => $apache_headers,
    'RAW_AUTH_HEADER' => $_SERVER['HTTP_AUTHORIZATION'] ?? 'NOT_SET',
    'REDIRECT_AUTH_HEADER' => $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? 'NOT_SET',
], JSON_PRETTY_PRINT);
