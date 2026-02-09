<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Sbc extends Model
{
    use HasFactory;

    protected $table = 'sbcs';

    protected $fillable = [
        'call_server_id',
        'name',
        'sip_server',
        'sip_server_port',
        'transport',
        'context',
        'codecs',
        'dtmfmode',
        'registration',
        'auth_username',
        'secret',
        'outcid',
        'maxchans',
        'qualify',
        'qualify_frequency',
        'description',
        'disabled',
    ];

    protected $casts = [
        'sip_server_port' => 'integer',
        'maxchans' => 'integer',
        'qualify' => 'boolean',
        'qualify_frequency' => 'integer',
        'disabled' => 'boolean',
    ];

    public static function getTransports(): array
    {
        return [
            'udp' => 'UDP',
            'tcp' => 'TCP',
            'tls' => 'TLS',
        ];
    }

    public static function getDtmfModes(): array
    {
        return [
            'auto' => 'Auto',
            'rfc4733' => 'RFC 4733',
            'inband' => 'Inband',
            'info' => 'SIP INFO',
        ];
    }

    public static function getRegistrations(): array
    {
        return [
            'none' => 'None',
            'send' => 'Send',
            'receive' => 'Receive',
        ];
    }

    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }
}
