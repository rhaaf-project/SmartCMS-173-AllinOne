<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ThirdPartyDevice extends Model
{
    protected $table = 'third_party_devices';
    
    protected $fillable = [
        'call_server_id',
        'extension',
        'name',
        'secret',
        'description',
        'type',
    ];

    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }
}