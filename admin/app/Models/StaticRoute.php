<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class StaticRoute extends Model
{
    protected $fillable = [
        'call_server_id',
        'network',
        'subnet',
        'gateway',
        'device',
        'description',
    ];

    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }
}
