<?php

namespace App\Http\Controllers\Api\V1\Recording;

use App\Http\Controllers\Controller;
use App\Models\Cdr;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class CdrController extends Controller
{
    /**
     * Display a listing of the CDRs.
     */
    public function index(Request $request): JsonResponse
    {
        $query = Cdr::query()->orderBy('calldate', 'desc');

        if ($request->has('src')) {
            $query->where('src', 'like', "%{$request->src}%");
        }

        if ($request->has('dst')) {
            $query->where('dst', 'like', "%{$request->dst}%");
        }

        if ($request->has('date_from')) {
            $query->whereDate('calldate', '>=', $request->date_from);
        }

        if ($request->has('date_to')) {
            $query->whereDate('calldate', '<=', $request->date_to);
        }

        $cdrs = $query->paginate($request->get('per_page', 20));

        // Append Recording URL logic
        $cdrs->getCollection()->transform(function ($cdr) {
            $cdr->setAppends(['recording_url']);
            return $cdr;
        });

        return response()->json($cdrs);
    }

    /**
     * Display the specified CDR.
     */
    public function show(Cdr $cdr): JsonResponse
    {
        return response()->json($cdr);
    }
}
