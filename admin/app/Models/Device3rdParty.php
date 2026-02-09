<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Device3rdParty extends Model
{
    protected $table = 'device_3rd_parties';
    
    protected $fillable = [
        'name',
        'mac_address',
        'ip_address',
        'device_type',
        'manufacturer',
        'model',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];
}