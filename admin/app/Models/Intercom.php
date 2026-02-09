<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Intercom extends Model
{
    use HasFactory;

    protected $fillable = [
        'call_server_id',
        'branch_id',
        'name',
        'extension',
        'description',
        'is_active',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Get the call server for this intercom
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    /**
     * Get the branch for this intercom
     */
    public function branch(): BelongsTo
    {
        return $this->belongsTo(Branch::class);
    }
}
