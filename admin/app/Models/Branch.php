<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Branch extends Model
{
    use HasFactory;

    protected $fillable = [
        'customer_id',
        'head_office_id',
        'call_server_id',
        'name',
        'code',
        'country',
        'province',
        'city',
        'district',
        'address',
        'contact_name',
        'contact_phone',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Get the customer that owns this branch
     */
    public function customer(): BelongsTo
    {
        return $this->belongsTo(Customer::class);
    }

    /**
     * Get the head office for this branch (optional)
     */
    public function headOffice(): BelongsTo
    {
        return $this->belongsTo(HeadOffice::class);
    }

    /**
     * Get the call server for this branch
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the extensions for this branch
     */
    public function extensions(): HasMany
    {
        return $this->hasMany(Extension::class);
    }

    /**
     * Get the lines for this branch
     */
    public function lines(): HasMany
    {
        return $this->hasMany(Line::class);
    }

    /**
     * Get display name with location
     */
    public function getDisplayNameAttribute(): string
    {
        return $this->city ? "{$this->name} ({$this->city})" : $this->name;
    }

    /**
     * Get full location string
     */
    public function getFullLocationAttribute(): string
    {
        $parts = array_filter([$this->district, $this->city, $this->province, $this->country]);
        return implode(', ', $parts);
    }
}
