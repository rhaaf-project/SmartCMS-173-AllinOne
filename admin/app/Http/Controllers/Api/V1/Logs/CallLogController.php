<?php

namespace App\Http\Controllers\Api\V1\Logs;

use App\Http\Controllers\Controller;
use App\Models\CallLog;
use Illuminate\Http\JsonResponse;

class CallLogController extends Controller
{
    public function index(): JsonResponse
    {
        $logs = CallLog::orderBy('created_at', 'desc')->get();

        return response()->json([
            'success' => true,
            'data' => $logs
        ]);
    }

    public function show(string $id): JsonResponse
    {
        $log = CallLog::findOrFail($id);

        return response()->json([
            'success' => true,
            'data' => $log
        ]);
    }

    public function destroy(string $id): JsonResponse
    {
        $log = CallLog::findOrFail($id);
        $log->delete();

        return response()->json([
            'success' => true,
            'message' => 'Call log deleted successfully'
        ]);
    }
}
