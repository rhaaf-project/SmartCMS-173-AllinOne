<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OutboundRoute extends Model
{
    use HasFactory;

    protected $fillable = [
        'call_server_id',
        'name',
        'trunk_id',
        'dial_pattern',
        'match_cid',
        'prepend_digits',
        'outcid',
        'priority',
        'is_active',
        'description',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'priority' => 'integer',
    ];

    /**
     * Get the call server for this outbound route
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the trunk for this outbound route
     */
    public function trunk(): BelongsTo
    {
        return $this->belongsTo(Trunk::class);
    }

    /**
     * Check if extension matches this route's pattern
     */
    public function matchesExtension(string $extension): bool
    {
        if (empty($this->match_cid)) {
            return true; // No filter = match all
        }

        // Convert FreePBX pattern (X = any digit) to regex
        $pattern = str_replace('X', '\d', $this->match_cid);
        return preg_match('/^' . $pattern . '$/', $extension) === 1;
    }
}
