<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\CallServer;
use Illuminate\Http\Request;

class CallServerController extends Controller
{
    public function index()
    {
        return CallServer::all();
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string',
            'host' => 'required|ipv4', // Harus IP valid
            'port' => 'required|integer', // Port AMI (biasanya 5038)
            'description' => 'nullable|string',
        ]);

        // LOGIC TEST KONEKSI REALTIME (Ping AMI)
        $host = $validated['host'];
        $port = $validated['port']; // Default 5038
        
        $connection = @fsockopen($host, $port, $errno, $errstr, 2); // Timeout 2 detik

        if (!$connection) {
            return response()->json([
                'message' => "Gagal terhubung ke Call Server ($host:$port). Pastikan Asterisk Docker aktif dan port AMI terbuka.",
                'error' => $errstr
            ], 400);
        }

        fclose($connection);

        // Jika konek, simpan ke DB
        $validated['is_active'] = true;
        $callServer = CallServer::create($validated);

        return response()->json([
            'message' => 'Call Server berhasil ditambahkan dan terhubung!',
            'data' => $callServer
        ], 201);
    }

    public function show($id)
    {
        return CallServer::findOrFail($id);
    }

    public function update(Request $request, $id)
    {
        $callServer = CallServer::findOrFail($id);
        $callServer->update($request->all());
        return response()->json($callServer);
    }

    public function destroy($id)
    {
        CallServer::destroy($id);
        return response()->json(null, 204);
    }
}
