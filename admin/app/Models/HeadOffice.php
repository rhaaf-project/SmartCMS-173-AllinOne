<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class HeadOffice extends Model
{
    use HasFactory;

    // Site Types
    const TYPE_BASIC = 'basic';  // Basic (single site) - 1 device
    const TYPE_HA = 'ha';        // High Availability - 3 devices
    const TYPE_FO = 'fo';        // Failover/Redundancy - 2 devices

    protected $fillable = [
        'customer_id',
        'name',
        'code',
        'type',
        'country',
        'province',
        'city',
        'district',
        'address',
        'contact_name',
        'contact_phone',
        'description',
        'is_active',
        'bcp_drc_server_id',  // Optional backup server
        'bcp_drc_enabled',    // BCP/DRC enabled toggle
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Get available site types
     */
    public static function getTypes(): array
    {
        return [
            self::TYPE_BASIC => 'Basic (Single Site)',
            self::TYPE_HA => 'HA (High Availability)',
            self::TYPE_FO => 'FO (Failover/Redundancy)',
        ];
    }

    /**
     * Get the customer that owns this head office
     */
    public function customer(): BelongsTo
    {
        return $this->belongsTo(Customer::class);
    }

    /**
     * Get the call servers at this head office site
     */
    public function callServers(): HasMany
    {
        return $this->hasMany(CallServer::class);
    }

    /**
     * Get the branches under this head office
     */
    public function branches(): HasMany
    {
        return $this->hasMany(Branch::class);
    }

    /**
     * Get display name with type
     */
    public function getDisplayNameAttribute(): string
    {
        $type = self::getTypes()[$this->type] ?? $this->type;
        return "{$this->name} - {$type}";
    }
}
