<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SbcRoute extends Model
{
    protected $fillable = [
        'sbc_id',
        'pattern',
        'prefix',
        'strip',
        'priority',
        'description',
    ];

    protected $casts = [
        'strip' => 'integer',
        'priority' => 'integer',
    ];

    public function sbc(): BelongsTo
    {
        return $this->belongsTo(Sbc::class);
    }
}
