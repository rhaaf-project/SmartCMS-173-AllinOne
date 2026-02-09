<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;


class RecordingServer extends Model
{
    protected $table = 'recording_servers';

    protected $fillable = [
        'ip_address',
        'port',
        'pbx_system_1_type',
        'pbx_system_1_ip',
        'pbx_system_1_port',
        'pbx_system_2_type',
        'pbx_system_2_ip',
        'pbx_system_2_port',
        'pbx_system_3_type',
        'pbx_system_3_ip',
        'pbx_system_3_port',
        'pbx_system_4_type',
        'pbx_system_4_ip',
        'pbx_system_4_port',
    ];

    protected $casts = [
        'is_enabled' => 'boolean',
    ];

    // PBX System Type options
    public static function getPbxSystemTypes(): array
    {
        return [
            'None' => '-None-',
            'Aastra' => 'Aastra',
            'Aastra Matra' => 'Aastra Matra',
            'Alcatel' => 'Alcatel',
            'Asterisk' => 'Asterisk',
            'Avaya' => 'Avaya',
            'Avaya DMCC' => 'Avaya DMCC',
            'Cisco' => 'Cisco',
            'Cisco BIB' => 'Cisco BIB',
            'Cisco SIP' => 'Cisco SIP',
            'Cisco SIP Fork' => 'Cisco SIP Fork',
            'Cisco Skinny' => 'Cisco Skinny',
            'E-Metrotel' => 'E-Metrotel',
            'Genesys' => 'Genesys',
            'Genesys Active Recording' => 'Genesys Active Recording',
            'Huawei' => 'Huawei',
            'Huawei Meeting Recording' => 'Huawei Meeting Recording',
            'LG' => 'LG',
            'Mitel' => 'Mitel',
            'Mitel SRC' => 'Mitel SRC',
            'Nortel' => 'Nortel',
            'Nortel MGCP' => 'Nortel MGCP',
            'Panasonic' => 'Panasonic',
            'Radio - Motorola' => 'Radio - Motorola',
            'Radio - Tait' => 'Radio - Tait',
            'Radio - Zenitel' => 'Radio - Zenitel',
            'RTP' => 'RTP',
            'Shoretel' => 'Shoretel',
            'Siemens' => 'Siemens',
            'Siemens H323' => 'Siemens H323',
            'Siemens OpenScape' => 'Siemens OpenScape',
            'SIP' => 'SIP',
            'SIP TCP' => 'SIP TCP',
            'SIP UDP' => 'SIP UDP',
            'Speakerbus' => 'Speakerbus',
            'Smart UCX Phone' => 'Smart UCX Phone',
            'Smart UCX Softphone' => 'Smart UCX Softphone',
            'Smart UCX Turret' => 'Smart UCX Turret',
            'Tadiran' => 'Tadiran',
            'Tadiran Active Recording' => 'Tadiran Active Recording',
            'Tadiran MGCP' => 'Tadiran MGCP',
            'CUSTOM' => 'CUSTOM',
        ];
    }

}
