<?php

namespace App\Http\Controllers\Api\V1\Connectivity;

use App\Http\Controllers\Controller;
use App\Models\Extension;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;

class ExtensionController extends Controller
{
    public function index()
    {
        return Extension::with(['callServer', 'branch'])->get();
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'extension_number' => 'required|unique:extensions',
            'name' => 'required',
            'type' => 'required', // Line, Extension, VPW, CAS, Intercom, SIP/3rd Party
            'call_server_id' => 'required|exists:call_servers,id',
            'branch_id' => 'nullable|exists:branches,id',
            // Secret optional di validasi awal, kita handle di logic
            'secret' => 'nullable|string|min:6'
        ]);

        // LOGIC KHUSUS: Transport & Secret
        if ($request->type === 'SIP/3rd Party') {
            // Tipe SIP Biasa (Phoner/IP Phone Fisik)
            $validated['transport'] = 'UDP';
            $validated['port'] = 5060;
            // Wajib input password sendiri
            if (empty($request->secret)) {
                return response()->json(['message' => 'Secret is required for 3rd Party devices'], 422);
            }
            $validated['secret'] = $request->secret;
        } else {
            // Tipe WebRTC (Line, Extension, VPW, CAS, Intercom)
            $validated['transport'] = 'WSS';
            $validated['port'] = 8089;
            // Force Default Password
            $validated['secret'] = 'Maja1234!';
        }

        // Default context
        $validated['context'] = 'from-internal';

        $extension = Extension::create($validated);

        // TODO: Trigger Sync AMI ke Asterisk disini (nanti)
        
        return response()->json($extension, 201);
    }

    public function show($id)
    {
        return Extension::findOrFail($id);
    }

    public function update(Request $request, $id)
    {
        $extension = Extension::findOrFail($id);
        $user = Auth::user(); // Cek siapa yang login

        $validated = $request->validate([
            'name' => 'required',
            'branch_id' => 'nullable|exists:branches,id',
            'secret' => 'nullable|string|min:6'
        ]);

        // LOGIC UPDATE SECRET
        if ($request->has('secret') && $request->secret != $extension->secret) {
            
            // 1. Jika tipe SIP/3rd Party, User boleh ubah password
            if ($extension->type === 'SIP/3rd Party') {
                $extension->secret = $request->secret;
            } 
            // 2. Jika tipe lain (WebRTC), Cek Privilege
            else {
                // Asumsi role disimpan di kolom 'role' atau 'is_super_admin'
                // Sesuaikan 'super_admin' dengan value role di database Anda
                if ($user->role === 'super_admin') {
                    $extension->secret = $request->secret;
                } else {
                    // Jika Admin biasa coba ubah password default -> Hiraukan atau Error
                    // Kita hiraukan saja agar tidak error di frontend, tapi tidak tersimpan
                    unset($validated['secret']); 
                }
            }
        }

        // Logic Transport tidak boleh diubah saat update (terkunci by Type)
        // Update data lainnya
        $extension->update($request->except(['transport', 'port', 'extension_number', 'call_server_id', 'type']));

        return response()->json($extension);
    }

    public function destroy($id)
    {
        Extension::destroy($id);
        return response()->json(null, 204);
    }
}
