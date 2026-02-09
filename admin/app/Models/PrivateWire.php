<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PrivateWire extends Model
{
    use HasFactory;

    protected $table = 'private_wires';

    protected $fillable = [
        'call_server_id',
        'name',
        'number',
        'destination',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }
}
