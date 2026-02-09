<?php
return [
    'paths' => ['api/*', 'sanctum/csrf-cookie', 'SmartCMS/api/*'], // Tambah path SmartCMS
    'allowed_methods' => ['*'],
    'allowed_origins' => ['*'], // Izinkan semua origin
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['*'],
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => false, // Set false jika pakai token Bearer murni
];
