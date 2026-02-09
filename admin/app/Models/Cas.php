<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Cas extends Model
{
    use HasFactory;

    protected $table = 'cas';

    // CAS types
    const TYPE_E_AND_M = 'e_and_m';       // Ear & Mouth signaling
    const TYPE_LOOP_START = 'loop_start'; // Loop start signaling
    const TYPE_GROUND_START = 'ground_start'; // Ground start signaling
    const TYPE_WINK = 'wink';             // Wink signaling

    protected $fillable = [
        'call_server_id',
        'name',
        'channel_number',
        'signaling_type',
        'trunk_id',
        'span',
        'timeslot',
        'description',
        'destination',
        'destination_local',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'channel_number' => 'integer',
        'span' => 'integer',
        'timeslot' => 'integer',
    ];

    /**
     * Get available CAS signaling types
     */
    public static function getSignalingTypes(): array
    {
        return [
            self::TYPE_E_AND_M => 'E&M (Ear & Mouth)',
            self::TYPE_LOOP_START => 'Loop Start',
            self::TYPE_GROUND_START => 'Ground Start',
            self::TYPE_WINK => 'Wink Start',
        ];
    }

    /**
     * Get the call server for this CAS
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the trunk for this CAS
     */
    public function trunk(): BelongsTo
    {
        return $this->belongsTo(Trunk::class);
    }
}
