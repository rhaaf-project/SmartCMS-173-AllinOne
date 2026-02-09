<?php

namespace App\Http\Controllers\Api\V1\Logs;

use App\Http\Controllers\Controller;
use App\Models\SystemLog;
use Illuminate\Http\JsonResponse;

class SystemLogController extends Controller
{
    public function index(): JsonResponse
    {
        $logs = SystemLog::orderBy('created_at', 'desc')->get();

        return response()->json([
            'success' => true,
            'data' => $logs
        ]);
    }

    public function show(string $id): JsonResponse
    {
        $log = SystemLog::findOrFail($id);

        return response()->json([
            'success' => true,
            'data' => $log
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        $log = SystemLog::findOrFail($id);
        $log->delete();

        return response()->json([
            'success' => true,
            'message' => 'System log deleted successfully'
        ]);
    }
}
