<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RecordingChannel extends Model
{
    protected $table = 'recording_channels';

    protected $fillable = [
        'no',
        'pbx_system',
        'extension_name',
        'group',
    ];

    // Auto-generate sequence number on creation
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if (empty($model->no)) {
                $maxNo = static::max('no') ?? 0;
                $model->no = $maxNo + 1;
            }
        });
    }

    // PBX System options (1-4 based on RecordingServer's 4 PBX systems)
    public static function getPbxSystemOptions(): array
    {
        return [
            '1' => 'PBX System 1',
            '2' => 'PBX System 2',
            '3' => 'PBX System 3',
            '4' => 'PBX System 4',
        ];
    }
}
