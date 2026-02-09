<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Line extends Model
{
    use HasFactory;

    // Line types
    const TYPE_PSTN = 'pstn';        // Public Switched Telephone Network
    const TYPE_SIP = 'sip';          // SIP Trunk Line
    const TYPE_PRI = 'pri';          // Primary Rate Interface
    const TYPE_BRI = 'bri';          // Basic Rate Interface

    protected $fillable = [
        'call_server_id',
        'name',
        'line_number',
        'type',
        'channel_count',
        'trunk_id',
        'description',
        'secret',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'channel_count' => 'integer',
    ];

    /**
     * Get available line types
     */
    public static function getTypes(): array
    {
        return [
            self::TYPE_PSTN => 'PSTN (Analog)',
            self::TYPE_SIP => 'SIP Trunk',
            self::TYPE_PRI => 'PRI (E1/T1)',
            self::TYPE_BRI => 'BRI (ISDN)',
        ];
    }

    /**
     * Get the call server for this line
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the trunk for this line
     */
    public function trunk(): BelongsTo
    {
        return $this->belongsTo(Trunk::class);
    }
}
