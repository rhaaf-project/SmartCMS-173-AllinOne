<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class InboundRoute extends Model
{
    use HasFactory;

    protected $fillable = [
        'call_server_id',
        'did_number',
        'description',
        'trunk_id',
        'destination_type',
        'destination_id',
        'cid_filter',
        'priority',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'priority' => 'integer',
    ];

    // Destination types
    const DEST_EXTENSION = 'extension';
    const DEST_RING_GROUP = 'ring_group';
    const DEST_IVR = 'ivr';
    const DEST_VOICEMAIL = 'voicemail';
    const DEST_HANGUP = 'hangup';

    /**
     * Get available destination types
     */
    public static function getDestinationTypes(): array
    {
        return [
            self::DEST_EXTENSION => 'Extension',
            self::DEST_RING_GROUP => 'Ring Group',
            self::DEST_IVR => 'IVR',
            self::DEST_VOICEMAIL => 'Voicemail',
            self::DEST_HANGUP => 'Hangup',
        ];
    }

    /**
     * Get the call server for this inbound route
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the trunk for this inbound route
     */
    public function trunk(): BelongsTo
    {
        return $this->belongsTo(Trunk::class);
    }

    /**
     * Get destination extension if destination_type is extension
     */
    public function destinationExtension(): BelongsTo
    {
        return $this->belongsTo(Extension::class, 'destination_id');
    }
}
