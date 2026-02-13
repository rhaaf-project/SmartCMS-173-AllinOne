<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Device3rdParty extends Model
{
    protected $table = 'device_3rd_parties';

    protected $fillable = [
    'call_server_id', // Tetap perlu (relasi ke server)
    'name',           // PENTING: Ini jadi "Caller ID Name"
    'username',       // PENTING: Ini jadi "Extension Number"
    'password',       // PENTING: Ini jadi "Secret"
    'description',    // Opsional (Catatan)
    'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];
}
