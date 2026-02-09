<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Vpw extends Model
{
    use HasFactory;

    protected $table = 'vpws';

    // VPW types
    const TYPE_POINT_TO_POINT = 'point_to_point';   // Direct connection
    const TYPE_MULTIPOINT = 'multipoint';            // Multiple endpoints
    const TYPE_BROADCAST = 'broadcast';              // One-to-many

    protected $fillable = [
        'call_server_id',
        'trunk_id',
        'name',
        'vpw_number',
        'type',
        'source_extension',
        'destination',
        'destination_local',
        'priority',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'priority' => 'integer',
    ];

    /**
     * Get available VPW types
     */
    public static function getTypes(): array
    {
        return [
            self::TYPE_POINT_TO_POINT => 'Point-to-Point',
            self::TYPE_MULTIPOINT => 'Multipoint',
            self::TYPE_BROADCAST => 'Broadcast',
        ];
    }

    /**
     * Get the call server for this VPW
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the trunk for this VPW
     */
    public function trunk(): BelongsTo
    {
        return $this->belongsTo(Trunk::class);
    }

    protected static function boot()
    {
        parent::boot();
        static::creating(function ($model) {
            if (empty($model->name) && !empty($model->vpw_number)) {
                $model->name = $model->vpw_number;
            }
        });
    }
}
