<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class Trunk extends Model
{
    use HasFactory;

    // Transport types
    const TRANSPORT_UDP = 'udp';
    const TRANSPORT_TCP = 'tcp';
    const TRANSPORT_TLS = 'tls';

    // Registration types
    const REG_NONE = 'none';
    const REG_OUTBOUND = 'outbound';
    const REG_INBOUND = 'inbound';

    protected $fillable = [
        'call_server_id',
        'name',
        'channelid',
        'outcid',
        'maxchans',
        'disabled',
        'sip_server',
        'sip_server_port',
        'transport',
        'context',
        'codecs',
        'dtmfmode',
        'registration',
        'auth_username',
        'secret',
        'qualify',
        'qualify_frequency',
    ];

    protected $casts = [
        'disabled' => 'boolean',
        'qualify' => 'boolean',
        'maxchans' => 'integer',
        'sip_server_port' => 'integer',
        'qualify_frequency' => 'integer',
    ];

    protected $hidden = [
        'secret',
    ];

    /**
     * Boot the model
     */
    protected static function boot()
    {
        parent::boot();

        // Auto-generate channelid from name if not provided
        static::creating(function (Trunk $trunk) {
            if (empty($trunk->channelid)) {
                $trunk->channelid = 'trunk_' . Str::slug($trunk->name, '_');
            }
        });

        static::updating(function (Trunk $trunk) {
            if (empty($trunk->channelid)) {
                $trunk->channelid = 'trunk_' . Str::slug($trunk->name, '_');
            }
        });
    }

    /**
     * Get the call server that owns this trunk
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get available transport options
     */
    public static function getTransports(): array
    {
        return [
            self::TRANSPORT_UDP => 'UDP',
            self::TRANSPORT_TCP => 'TCP',
            self::TRANSPORT_TLS => 'TLS',
        ];
    }

    /**
     * Get available registration options
     */
    public static function getRegistrations(): array
    {
        return [
            self::REG_NONE => 'None',
            self::REG_OUTBOUND => 'Outbound',
            self::REG_INBOUND => 'Inbound',
        ];
    }

    /**
     * Get available codec options
     */
    public static function getCodecs(): array
    {
        return [
            'ulaw' => 'G.711 μ-law (ulaw)',
            'alaw' => 'G.711 A-law (alaw)',
            'gsm' => 'GSM',
            'g722' => 'G.722',
            'g726' => 'G.726',
            'opus' => 'Opus',
        ];
    }

    /**
     * Get available DTMF modes
     */
    public static function getDtmfModes(): array
    {
        return [
            'auto' => 'Auto',
            'rfc4733' => 'RFC 4733',
            'inband' => 'Inband',
            'info' => 'SIP INFO',
        ];
    }
}
