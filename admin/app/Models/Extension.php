<?php

namespace App\Models;

// use App\Services\AsteriskService; // TODO: Re-enable when implemented
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Log;

class Extension extends Model
{
    use HasFactory;

    // Extension types
    const TYPE_WEBRTC = 'webrtc';
    const TYPE_SOFTPHONE = 'softphone';

    protected $fillable = [
        'call_server_id',
        'extension',
        'type',
        'name',
        'secret',
        'context',
        'is_active',
        'user_id',
    ];

    protected $casts = [
        'is_active' => 'boolean',
    ];

    /**
     * Get available extension types
     */
    public static function getTypes(): array
    {
        return [
            self::TYPE_WEBRTC => 'WebRTC (Browser/Turret)',
            self::TYPE_SOFTPHONE => 'Softphone (Zoiper/Phoner)',
        ];
    }

    /**
     * Get the call server for this extension
     */
    public function callServer(): BelongsTo
    {
        return $this->belongsTo(CallServer::class);
    }

    // /**
    //  * Boot the model and add Asterisk sync events
    //  * TODO: Re-enable this when AsteriskService is implemented
    //  */
    // protected static function boot()
    // {
    //     parent::boot();
    //
    //     // Sync to Asterisk on create
    //     static::created(function (Extension $ext) {
    //         if ($ext->is_active) {
    //             try {
    //                 // $asterisk = app(AsteriskService::class);
    //                 // $asterisk->addExtension($ext->extension, $ext->secret, $ext->name, $ext->type);
    //                 // Log::info("[Extension] Synced to Asterisk: {$ext->extension} (type: {$ext->type})");
    //             } catch (\Exception $e) {
    //                 Log::warning("[Extension] Failed to sync to Asterisk: " . $e->getMessage());
    //             }
    //         }
    //     });
    //
    //     // Resync to Asterisk on update
    //     static::updated(function (Extension $ext) {
    //         try {
    //             // $asterisk = app(AsteriskService::class);
    //
    //             // If extension was deactivated, remove from Asterisk
    //             if (!$ext->is_active && $ext->wasChanged('is_active')) {
    //                 // $asterisk->removeExtension($ext->extension);
    //                 // Log::info("[Extension] Removed from Asterisk (deactivated): {$ext->extension}");
    //             }
    //             // If extension, secret, or type changed, resync
    //             elseif ($ext->wasChanged(['extension', 'secret', 'type'])) {
    //                 // $original = $ext->getOriginal('extension');
    //                 // $asterisk->removeExtension($original);
    //                 // $asterisk->addExtension($ext->extension, $ext->secret, $ext->name, $ext->type);
    //                 // Log::info("[Extension] Resynced to Asterisk: {$ext->extension} (type: {$ext->type})");
    //             }
    //         } catch (\Exception $e) {
    //            // Log::warning("[Extension] Failed to resync to Asterisk: " . $e->getMessage());
    //         }
    //     });
    //
    //     // Remove from Asterisk on delete
    //     static::deleted(function (Extension $ext) {
    //         try {
    //             // $asterisk = app(AsteriskService::class);
    //             // $asterisk->removeExtension($ext->extension);
    //             // Log::info("[Extension] Removed from Asterisk: {$ext->extension}");
    //         } catch (\Exception $e) {
    //             // Log::warning("[Extension] Failed to remove from Asterisk: " . $e->getMessage());
    //         }
    //     });
    // }

    /**
     * Get the user that owns this extension
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
