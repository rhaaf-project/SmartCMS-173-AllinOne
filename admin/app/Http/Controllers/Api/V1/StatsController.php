<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class StatsController extends Controller
{
    public function index()
    {
        // Since we don't have all tables yet, return mock data structure
        // You can replace with actual model queries when tables are ready

        $stats = [
            'ho' => [
                'active' => $this->getCount('head_offices', 'is_active', true),
                'inactive' => $this->getCount('head_offices', 'is_active', false),
            ],
            'branch' => [
                'active' => $this->getCount('branches', 'is_active', true),
                'inactive' => $this->getCount('branches', 'is_active', false),
            ],
            'callServer' => [
                'active' => $this->getCount('call_servers', 'is_active', true),
                'inactive' => $this->getCount('call_servers', 'is_active', false),
            ],
            'users' => [
                'active' => $this->getCount('users'),
                'inactive' => 0,
            ],
            'line' => [
                'active' => $this->getCount('lines', 'is_active', true),
                'inactive' => $this->getCount('lines', 'is_active', false),
            ],
            'extension' => [
                'active' => $this->getCount('extensions'),
                'inactive' => 0,
            ],
            'vpw' => [
                'active' => $this->getCount('vpws', 'is_active', true),
                'inactive' => $this->getCount('vpws', 'is_active', false),
            ],
            'cas' => [
                'active' => $this->getCount('cas', 'is_active', true),
                'inactive' => $this->getCount('cas', 'is_active', false),
            ],
            'trunk' => [
                'active' => $this->getCount('trunks', 'disabled', false),
                'inactive' => $this->getCount('trunks', 'disabled', true),
            ],
            'sbc' => [
                'active' => $this->getCount('sbcs', 'disabled', false),
                'inactive' => $this->getCount('sbcs', 'disabled', true),
            ],
            'privateWire' => [
                'active' => $this->getCount('private_wires', 'is_active', true),
                'inactive' => $this->getCount('private_wires', 'is_active', false),
            ],
            'intercom' => [
                'active' => $this->getCount('intercoms', 'is_active', true),
                'inactive' => $this->getCount('intercoms', 'is_active', false),
            ],
            'inboundRoute' => [
                'active' => $this->getCount('inbound_routes'),
                'inactive' => 0,
            ],
            'outboundRoute' => [
                'active' => $this->getCount('outbound_routes'),
                'inactive' => 0,
            ],
            'thirdParty' => [
                'active' => 0, // Placeholder
                'inactive' => 0,
            ],
        ];

        return response()->json([
            'success' => true,
            'data' => $stats,
        ]);
    }

    private function getCount($table, $column = null, $value = null)
    {
        try {
            // Check if table exists
            $tableExists = DB::select("SHOW TABLES LIKE '{$table}'");

            if (empty($tableExists)) {
                return 0;
            }

            $query = DB::table($table);

            if ($column !== null && $value !== null) {
                $query->where($column, $value);
            }

            return $query->count();
        } catch (\Exception $e) {
            // If table doesn't exist or error, return 0
            return 0;
        }
    }
}
