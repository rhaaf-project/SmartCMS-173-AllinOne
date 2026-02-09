<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class CallServer extends Model
{
    use HasFactory;

    protected $fillable = [
        'head_office_id',
        'name',
        'host',
        'port',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'port' => 'integer',
    ];

    // Site Types (for reference when HO assigns servers)
    const SITE_HA = 'ha';      // High Availability (3 devices)
    const SITE_FO = 'fo';      // Failover (2 devices)
    const SITE_BCP = 'bcp';    // Business Continuity Plan
    const SITE_DRC = 'drc';    // Disaster Recovery Center

    /**
     * Get the head office this server belongs to
     */
    public function headOffice(): \Illuminate\Database\Eloquent\Relations\BelongsTo
    {
        return $this->belongsTo(HeadOffice::class);
    }

    /**
     * Get the trunks for this call server
     */
    public function trunks(): HasMany
    {
        return $this->hasMany(Trunk::class);
    }

    /**
     * Get the extensions for this call server
     */
    public function extensions(): HasMany
    {
        return $this->hasMany(Extension::class);
    }

    /**
     * Get the lines for this call server
     */
    public function lines(): HasMany
    {
        return $this->hasMany(Line::class);
    }

    /**
     * Get the VPWs for this call server
     */
    public function vpws(): HasMany
    {
        return $this->hasMany(Vpw::class);
    }

    /**
     * Get the CAS channels for this call server
     */
    public function cas(): HasMany
    {
        return $this->hasMany(Cas::class);
    }

    /**
     * Get the inbound routes for this call server
     */
    public function inboundRoutes(): HasMany
    {
        return $this->hasMany(InboundRoute::class);
    }

    /**
     * Get the outbound routes for this call server
     */
    public function outboundRoutes(): HasMany
    {
        return $this->hasMany(OutboundRoute::class);
    }

    /**
     * Get display name with host
     */
    public function getDisplayNameAttribute(): string
    {
        return "{$this->name} ({$this->host})";
    }
}
