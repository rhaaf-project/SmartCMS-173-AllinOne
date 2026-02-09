<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Firewall extends Model
{
    protected $table = 'firewalls';

    protected $fillable = [
        'call_server_id',
        'port',
        'source',
        'destination',
        'protocol',
        'interface',
        'direction',
        'action',
        'comment',
        'is_enabled',
    ];

    protected $casts = [
        'is_enabled' => 'boolean',
    ];

    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }
}
