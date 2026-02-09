<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

// === IMPORT CONTROLLERS ===
use App\Http\Controllers\Api\V1\StatsController;
use App\Http\Controllers\Api\V1\CallServerController;
use App\Http\Controllers\Api\V1\Connectivity\ExtensionController;
use App\Http\Controllers\Api\V1\Connectivity\TrunkController;
use App\Http\Controllers\Api\V1\Connectivity\IntercomController;
// use App\Http\Controllers\Api\V1\Connectivity\InboundRouteController; // Masih error class not found? Uncomment kalau sudah fix
// use App\Http\Controllers\Api\V1\Connectivity\OutboundRouteController; // Masih error class not found? Uncomment kalau sudah fix
use App\Http\Controllers\Api\V1\Organization\CompanyController;
use App\Http\Controllers\Api\V1\Organization\HeadOfficeController;
use App\Http\Controllers\Api\V1\Organization\BranchController;
use App\Http\Controllers\Api\V1\Organization\SubBranchController;
use App\Http\Controllers\Api\V1\Sbc\SbcController;
use App\Http\Controllers\Api\V1\Recording\CdrController;
use App\Http\Controllers\Api\V1\Logs\SystemLogController;
use App\Http\Controllers\Api\V1\Logs\ActivityLogController;
use App\Http\Controllers\Api\V1\Logs\CallLogController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// ==============================================================================
// 1. PUBLIC ROUTES (BEBAS AKSES - LOGIN DISINI)
// ==============================================================================
Route::prefix('v1')->group(function () {

    Route::post('/login', function (Request $request) {
        
        // 1. Validasi (Hapus |email agar username juga bisa masuk)
        $request->validate([
            'email' => 'required', 
            'password' => 'required',
        ]);

        // 2. Deteksi apakah input Email atau Username
        $field = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

        // 3. Cari User
        $user = User::where($field, $request->email)->first();

        // 4. Cek Password
        if (! $user || ! Hash::check($request->password, $user->password)) {
            // Return 401 Unauthorized (Credential Invalid)
            return response()->json([
                'message' => 'Login Gagal. Username/Email atau Password salah.'
            ], 401);
        }

        // 5. Hapus token lama & Buat baru
        $user->tokens()->delete();
        $tokenStr = $user->createToken('SmartCMS-Token')->plainTextToken;

        // 6. Return Response (Format Shotgun untuk Frontend)
        return response()->json([
            'token' => $tokenStr,
            'access_token' => $tokenStr,
            'accessToken' => $tokenStr,
            'auth_token' => $tokenStr,
            'user' => $user
        ]);
    });

});

// ==============================================================================
// 2. PROTECTED ROUTES (HARUS LOGIN / ADA TOKEN)
// ==============================================================================
Route::middleware('auth:sanctum')->prefix('v1')->group(function () {

    // --- UTILS ---
    Route::get('/user', function (Request $request) {
        return $request->user();
    });

    Route::get('/stats', [StatsController::class, 'index']);

    // --- CONNECTIVITY ---
    Route::apiResource('call-servers', CallServerController::class);
    Route::apiResource('extensions', ExtensionController::class);
    Route::apiResource('trunks', TrunkController::class);
    Route::apiResource('intercoms', IntercomController::class);

    // Alias routes untuk frontend (Kompatibilitas)
    Route::get('lines', [ExtensionController::class, 'index']); 
    Route::get('vpws', [ExtensionController::class, 'index']);
    Route::get('cas', [ExtensionController::class, 'index']);
    Route::get('device-3rd-parties', [ExtensionController::class, 'index']);

    // Routing (Uncomment jika file controller sudah ada & fixed)
    // Route::apiResource('inbound-routes', InboundRouteController::class);
    // Route::apiResource('outbound-routes', OutboundRouteController::class);

    // --- SBC ---
    Route::apiResource('sbcs', SbcController::class);
    Route::get('private-wires', [SbcController::class, 'index']);
    Route::get('sbc-routes', [SbcController::class, 'index']);

    // --- ORGANIZATION ---
    Route::apiResource('companies', CompanyController::class);
    Route::apiResource('head-offices', HeadOfficeController::class);
    Route::apiResource('branches', BranchController::class);
    Route::apiResource('sub-branches', SubBranchController::class);
    Route::get('topology', [CompanyController::class, 'topology']);

    // --- LOGS ---
    Route::apiResource('system-logs', SystemLogController::class);
    Route::apiResource('activity-logs', ActivityLogController::class);
    Route::apiResource('call-logs', CallLogController::class);
    Route::apiResource('cdrs', CdrController::class);
});