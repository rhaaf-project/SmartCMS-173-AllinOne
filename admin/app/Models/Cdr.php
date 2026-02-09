<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Cdr extends Model
{
    use HasFactory;

    protected $table = 'cdrs';

    protected $fillable = [
        'calldate',
        'clid',
        'src',
        'dst',
        'dcontext',
        'channel',
        'dstchannel',
        'lastapp',
        'lastdata',
        'duration',
        'billsec',
        'disposition',
        'amaflags',
        'accountcode',
        'uniqueid',
        'userfield',
        'did',
        'recordingfile',
        'cnum',
        'cnam',
        'outbound_cnum',
        'outbound_cnam',
        'dst_cnam',
        'linkedid',
        'peeraccount',
        'sequence',
    ];

    protected $casts = [
        'calldate' => 'datetime',
        'duration' => 'integer',
        'billsec' => 'integer',
        'sequence' => 'integer',
        'amaflags' => 'integer',
    ];

    /**
     * Check if call was answered
     */
    public function isAnswered(): bool
    {
        return $this->disposition === 'ANSWERED';
    }

    /**
     * Get recording URL (placeholder logic)
     */
    public function getRecordingUrlAttribute(): ?string
    {
        if (empty($this->recordingfile)) {
            return null;
        }
        // TODO: Implement actual URL generation logic based on storage
        return "/storage/recordings/{$this->recordingfile}";
    }
}
