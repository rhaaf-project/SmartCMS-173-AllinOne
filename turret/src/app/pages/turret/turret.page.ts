// TurretPage - SmartX UI Port to Angular/Ionic - rebuild
import { Component, OnInit, OnDestroy, CUSTOM_ELEMENTS_SCHEMA, ChangeDetectorRef, HostListener } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { IonicModule } from '@ionic/angular';
import { HttpClientModule } from '@angular/common/http';
import { SipService } from '../../services/sip.service';
import { AudioService } from '../../services/audio.service';
import { LaravelAuthService, Line, VPW, CAS, Intercom, PhonebookEntry, ChannelState, SystemConfig } from '../../services/laravel-auth.service';
import { VERSION } from '../../version';

declare var bootstrap: any; // Bootstrap JS

export interface ChannelRecording {
    id: string;
    color: string;
}

export interface Channel {
    key: string;
    name: string;
    extension: string;
    type: 'sip' | 'whatsapp' | 'teams';
    position: number;
    isActive: boolean;      // SIP connected (green)
    isCalling: boolean;     // Currently calling/ringing (yellow)
    isPtt: boolean;
    isSelected: boolean;
    volumeIn: number;
    volumeOut: number;
    groups: string[];
    channelRecordings?: ChannelRecording[];  // Max 3 recordings per channel
}

export interface Group {
    id: string;
    name: string;
    isActive: boolean;
    channels: string[];
}

export interface Extension {
    number: string;
    online: boolean;
}

export interface Contact {
    id: string;
    name: string;
    phones: string[];  // Multiple phone numbers
    expanded?: boolean;
}

export interface Recording {
    id: string;
    name: string;
    duration?: string;
    date?: string;
    filePath?: string;  // Base64 data URL or file path
}

export interface Tab {
    id: string;
    title: string;
    isClosable: boolean;
    panelType: 'dashboard' | 'fav' | 'whatsapp' | 'teams' | 'audiorec' | 'grouptalk' | 'audio' | 'info';
    isEditMode?: boolean;  // For FAV tabs view/edit toggle
    items: (DashboardIcon | null)[];  // 24-slot grid per tab (empty array for panel tabs)
}

export interface DashboardIcon {
    id: string;
    label: string;
    icon: string;
    color: string;
    bgColor: string;
    panel?: string;
    isDeletable?: boolean;
}

@Component({
    selector: 'app-turret',
    standalone: true,
    imports: [CommonModule, IonicModule, FormsModule, HttpClientModule],
    schemas: [CUSTOM_ELEMENTS_SCHEMA],
    templateUrl: './turret.page.html',
    styleUrls: ['./turret.page.scss']
})
export class TurretPage implements OnInit, OnDestroy {
    // Header
    currentDate = '';
    appVersion = VERSION.fullString;
    currentTime = '';
    pttTargetName = 'Unknown Channel';

    // Incoming Call
    incomingCall: { number: string; channelKey: string } | null = null;

    // Channels (16)
    channels: Channel[] = [];
    selectedChannel: Channel | null = null;

    // Groups
    groups: Group[] = [
        { id: 'G1', name: 'Group 1', isActive: false, channels: [] },
        { id: 'G2', name: 'Group 2', isActive: false, channels: [] },
        { id: 'G3', name: 'Group 3', isActive: false, channels: [] }
    ];

    // Virtual Keyboard State
    vkActive = false;
    vkShift = false;
    vkSymbols = false;
    vkInput: HTMLInputElement | null = null;
    vkFirstKey = true;  // [FIX] Track if first key after VK opens (for select-all replace)

    // Login State
    showLogin = true;  // Show login on start
    loginUsername = '';
    loginPassword = '';
    loginStatus = 'System Ready';
    loginStatusColor = '#666';

    // PTT State
    pttActive = false;
    private pttJustFired = false;

    // Dialpad State
    dialpadNumber = '';
    dialpadContactName = '';
    dialpadConnected = false;
    dialpadCallerName = '';
    dialpadSession: any = null;
    dialpadDrawerOpen = false;

    // Active incoming call (waiting for user to drag to channel)
    activeIncomingSessionKey: string | null = null;
    activeIncomingNumber: string | null = null;

    // Duplicate Modal State
    showDuplicateModal = false;
    duplicateModalMessage = '';

    // Audio Device State
    audioInputDevices: { deviceId: string; label: string }[] = [];
    audioOutputDevices: { deviceId: string; label: string }[] = [];
    selectedInputDeviceId = 'default';
    selectedOutputDeviceId = 'default';

    // Per-channel volume (0-100)
    channelVolumes: Map<string, number> = new Map();
    volumeDragChannel: Channel | null = null;
    volumeDragStartY = 0;
    volumeDragStartValue = 0;

    // Audio Recordings
    recordings: Recording[] = [];
    isRecording = false;
    mediaRecorder: MediaRecorder | null = null;
    recordingChunks: Blob[] = [];
    recordingStartTime = 0;
    currentRecordingName = '';
    showRecordingPanel = false;
    recordingTimer = '00:00';
    recordingComplete = false;
    timerInterval: any = null;
    editingRecording: Recording | null = null;
    showDeleteModal = false;
    pendingDeleteRecording: Recording | null = null;
    playingRecordingId: string | null = null;
    currentAudio: HTMLAudioElement | null = null;

    // SmartX Audio Colors (cycling)
    readonly AUDIO_COLORS = ['#ff6b6b', '#ffc107', '#45b7d1'];  // red, yellow, blue
    audioColorIndex = 0;

    // Loop Playback State
    isPlayingLoop = false;
    loopAudioQueue: string[] = [];
    loopCurrentIndex = 0;

    // Current SIP Extension
    currentExtension = '';

    // === TABS SYSTEM ===
    tabs: Tab[] = [];
    activeTabId = 'dashboard';

    // Get current active tab
    get activeTab(): Tab | undefined {
        return this.tabs.find(t => t.id === this.activeTabId);
    }

    // Get current tab's items (for template binding)
    get dashboardLayout(): (DashboardIcon | null)[] {
        return this.activeTab?.items || [];
    }

    // Check if active tab matches a panel type (for HTML template conditional rendering)
    isPanelActive(panelType: Tab['panelType']): boolean {
        return this.activeTab?.panelType === panelType;
    }

    // Initialize tabs with default dashboard
    private initTabs(): void {
        this.tabs = [{
            id: 'dashboard',
            title: 'DASHBOARD',
            isClosable: false,
            panelType: 'dashboard',
            items: this.createDefaultDashboardItems()
        }];
        this.activeTabId = 'dashboard';
        console.log('📑 Tabs initialized:', this.tabs.length, 'tabs, activeTabId:', this.activeTabId);
    }

    private createDefaultDashboardItems(): (DashboardIcon | null)[] {
        const items: (DashboardIcon | null)[] = new Array(24).fill(null);
        items[0] = { id: 'whatsapp', label: 'WhatsApp', icon: 'chat', color: '#25d366', bgColor: 'rgba(37, 211, 102, 0.2)', panel: 'whatsapp', isDeletable: false };
        items[1] = { id: 'teams', label: 'Teams', icon: 'groups', color: '#6264a7', bgColor: 'rgba(98, 100, 167, 0.2)', panel: 'teams', isDeletable: false };
        items[2] = { id: 'audiorec', label: 'Audio Rec', icon: 'play_circle', color: '#888', bgColor: 'rgba(255, 255, 255, 0.1)', panel: 'recordings', isDeletable: false };
        items[3] = { id: 'grouptalk', label: 'Group Talk', icon: 'record_voice_over', color: '#ff9800', bgColor: 'rgba(255, 152, 0, 0.2)', panel: 'grouptalk', isDeletable: false };
        items[4] = { id: 'audio', label: 'Audio', icon: 'graphic_eq', color: '#00bcd4', bgColor: 'rgba(0, 188, 212, 0.2)', panel: 'audio', isDeletable: false };
        return items;
    }

    switchTab(tabId: string): void {
        this.activeTabId = tabId;
        console.log('Switched to tab:', tabId);
    }

    addNewTab(): void {
        const newTabId = `fav-${Date.now()}`;
        const newTab: Tab = {
            id: newTabId,
            title: `FAV ${this.tabs.length}`,
            isClosable: true,
            panelType: 'fav',
            isEditMode: true,  // Start in edit mode like SmartX
            items: new Array(24).fill(null)
        };
        this.tabs.push(newTab);
        this.activeTabId = newTabId;
        this.favRenameInput = newTab.title;  // Set rename input value
        console.log('🆕 Added new tab:', newTab.title, 'activeTabId:', this.activeTabId);
        console.log('📋 All tabs:', this.tabs.map(t => t.id));
    }

    closeTab(tabId: string, event: Event): void {
        event.stopPropagation();
        const tab = this.tabs.find(t => t.id === tabId);
        if (!tab || !tab.isClosable) return;

        const index = this.tabs.findIndex(t => t.id === tabId);
        this.tabs.splice(index, 1);

        // Switch to previous tab or dashboard
        if (this.activeTabId === tabId) {
            this.activeTabId = this.tabs[Math.max(0, index - 1)]?.id || 'dashboard';
        }
        console.log('Closed tab:', tabId);
    }

    // FAV Tab rename input value (for edit mode)
    favRenameInput = '';

    // Enable edit mode for FAV tab
    enableFavEditMode(tabId: string): void {
        const tab = this.tabs.find(t => t.id === tabId);
        if (tab && tab.isClosable) {
            tab.isEditMode = true;
            this.favRenameInput = tab.title;
            console.log('Edit mode enabled for:', tab.title);
        }
    }

    // Save FAV tab rename AND create dashboard icon
    saveFavEdit(tabId: string): void {
        const tab = this.tabs.find(t => t.id === tabId);
        if (tab && this.favRenameInput.trim()) {
            tab.title = this.favRenameInput.trim();
            tab.isEditMode = false;

            // 1. Save to savedFavourites in localStorage
            const savedFavourites = JSON.parse(localStorage.getItem('smartucx_saved_favourites') || '{}');
            savedFavourites[tabId] = {
                title: tab.title,
                items: tab.items.filter(i => i !== null)
            };
            localStorage.setItem('smartucx_saved_favourites', JSON.stringify(savedFavourites));

            // 2. Add OR update fav icon in dashboard layout
            const dashboardTab = this.tabs.find(t => t.id === 'dashboard');
            if (dashboardTab) {
                const favIconId = `fav_${tabId}`;
                const existingIconIndex = dashboardTab.items.findIndex(item => item?.id === favIconId);

                if (existingIconIndex !== -1) {
                    // Update existing icon label
                    dashboardTab.items[existingIconIndex]!.label = tab.title;
                    console.log(`⭐ Updated ${tab.title} icon in dashboard slot ${existingIconIndex}`);
                } else {
                    // Add new icon to empty slot
                    const emptySlotIndex = dashboardTab.items.findIndex(item => item === null);
                    if (emptySlotIndex !== -1) {
                        dashboardTab.items[emptySlotIndex] = {
                            id: favIconId,
                            label: tab.title,
                            icon: 'star',
                            color: 'gold',
                            bgColor: '#333',
                            panel: `favourite_${tabId}`,
                            isDeletable: true
                        };
                        console.log(`⭐ Added ${tab.title} icon to dashboard slot ${emptySlotIndex}`);
                    }
                }
            }

            // 3. Hide VK
            this.hideVirtualKeyboard();

            console.log('✅ Saved favourite:', tab.title);
        }
    }

    // Cancel edit mode
    cancelFavEdit(tabId: string): void {
        const tab = this.tabs.find(t => t.id === tabId);
        if (tab) {
            tab.isEditMode = false;
            this.hideVirtualKeyboard();
            console.log('Cancelled edit for:', tab.title);
        }
    }

    // Focus rename input and show VK
    focusRenameInput(): void {
        setTimeout(() => {
            const input = document.querySelector('.fav-rename-input') as HTMLInputElement;
            if (input) {
                input.focus();
                this.showVirtualKeyboard();
                console.log('📝 Rename input focused, VK shown');
            }
        }, 100);
    }

    // Show virtual keyboard (uses vkActive Angular property)
    showVirtualKeyboard(): void {
        this.vkActive = true;
        console.log('⌨️ VK shown');
    }

    // Hide virtual keyboard
    hideVirtualKeyboard(): void {
        this.vkActive = false;
        console.log('⌨️ VK hidden');
    }


    // Legacy renameTab (prompt-based, for double-click in tab bar)
    renameTab(tabId: string): void {
        const tab = this.tabs.find(t => t.id === tabId);
        if (tab && tab.isClosable) {
            const newName = prompt('Enter new tab name:', tab.title);
            if (newName) {
                tab.title = newName;
            }
        }
    }

    // Drag & Drop State
    draggedChannel: Channel | null = null;
    dragOverChannel: string | null = null;
    draggedIcon: any = null;
    dragOverEmptyCell: number | null = null;
    dragOverTrash = false;
    dragOverActionBtn: string | null = null;

    // Footer
    systemStatus = 'READY';
    connectionStatus = 'LOW LATENCY';
    traderId = '4759';

    // Drawer: Submenu state
    submenuOpen: string | null = null;

    // Drawer: Lines, VPW, CAS (loaded from CMS API)
    lines: { id: string; name: string; use_ext: string }[] = [];
    vpwList: { id: string; name: string; use_ext: string }[] = [];
    casList: { id: string; name: string; use_ext: string }[] = [];

    // Drawer: Extensions (loaded from CMS API)
    extensions: Extension[] = [];

    // System Config (loaded from CMS API)
    sipServer = '103.154.80.172';  // Default, will be overwritten by API
    private currentTurretUserId = 1;  // TODO: Get from logged in user
    private channelStateMap = new Map<string, number>();  // Map channel_key to db id for updates

    // Drawer: Intercom (loaded from CMS API)
    intercomContacts: { name: string; ext: string }[] = [];

    // Drawer: Phonebook
    phoneSearchQuery = '';
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
    contacts: Contact[] = [];
    filteredContacts: Contact[] = [];

    // Drawer: Recordings
    audioRecordings: Recording[] = [
        { id: '1', name: 'Meeting Notes', duration: '02:30' },
        { id: '2', name: 'Client Call', duration: '05:15' }
    ];
    callRecordings: Recording[] = [
        { id: '1', name: 'Call with VPW', date: '2025-12-18' }
    ];

    // Timer
    private clockInterval: any;

    constructor(
        private sipService: SipService,
        public audioService: AudioService,
        private cdr: ChangeDetectorRef,
        private laravelAuth: LaravelAuthService
    ) { }

    ngOnInit(): void {
        this.initChannels();
        this.initContacts();
        this.initTabs();
        this.loadRecordings();
        this.loadTurretData();  // Load Lines, VPW, CAS, Intercom from CMS API
        this.startClock();
        this.audioService.resumeContext();
        this.setupPttListener();
        this.setupVkTouchListener();
        this.setupSipSubscriptions();  // [FIX] Subscribe to SIP events
        this.setupAudioDeviceSubscriptions();  // [FIX] Subscribe to audio devices
        this.setupAudioUnlock();  // [FIX] Unlock audio on first user interaction
    }

    // [FIX] Unlock audio autoplay on first user interaction
    private audioUnlocked = false;
    private setupAudioUnlock(): void {
        const unlockAudio = () => {
            if (this.audioUnlocked) return;
            this.audioUnlocked = true;

            // Resume AudioContext
            this.audioService.resumeContext();

            // Try to play remoteAudio element (will succeed after user gesture)
            const remoteAudio = document.getElementById('remoteAudio') as HTMLAudioElement;
            if (remoteAudio && remoteAudio.srcObject) {
                remoteAudio.play().catch(() => { });
            }

            console.log('[Audio] 🔓 Audio unlocked by user interaction');

            // Remove listeners after first unlock
            document.removeEventListener('click', unlockAudio);
            document.removeEventListener('touchstart', unlockAudio);
            document.removeEventListener('keydown', unlockAudio);
        };

        document.addEventListener('click', unlockAudio);
        document.addEventListener('touchstart', unlockAudio);
        document.addEventListener('keydown', unlockAudio);
    }

    // [FIX] Subscribe to audio device changes
    private setupAudioDeviceSubscriptions(): void {
        this.audioService.inputDevices$.subscribe(devices => {
            this.audioInputDevices = devices;
            console.log('[Audio] Input devices updated:', devices.length);
        });

        this.audioService.outputDevices$.subscribe(devices => {
            this.audioOutputDevices = devices;
            console.log('[Audio] Output devices updated:', devices.length);
        });
    }

    // [FIX] Subscribe to SIP service events for UI updates
    private activeChannelKeys = new Set<string>();  // Track which channels have active calls
    private incomingSessionChannelMap = new Map<string, string>();  // Map incoming session key to channel key

    private setupSipSubscriptions(): void {
        // Watch for session state changes
        this.sipService.activeSessions$.subscribe(sessions => {
            // Check for new connected sessions
            sessions.forEach((sipSession, channelKey) => {
                const index = this.channels.findIndex(c => c.key === channelKey);
                if (index !== -1) {
                    if (sipSession.state === 'connected') {
                        // Call connected - update to active (green)
                        this.channels[index] = {
                            ...this.channels[index],
                            isCalling: false,
                            isActive: true
                        };
                        this.activeChannelKeys.add(channelKey);
                        console.log('✅ SIP Connected:', channelKey);
                    }
                }
            });

            // Check for ended sessions (channel was active but no longer in sessions)
            this.activeChannelKeys.forEach(channelKey => {
                if (!sessions.has(channelKey)) {
                    const index = this.channels.findIndex(c => c.key === channelKey);
                    if (index !== -1) {
                        // Call ended - reset channel state
                        this.channels[index] = {
                            ...this.channels[index],
                            isCalling: false,
                            isActive: false
                        };
                        console.log('📴 SIP Session ended:', channelKey);
                    }
                    this.activeChannelKeys.delete(channelKey);

                    // Reset dialpad state when any call ends
                    this.dialpadConnected = false;
                    this.dialpadCallerName = '';
                    this.activeIncomingSessionKey = null;
                    this.activeIncomingNumber = null;
                }
            });

            this.channels = [...this.channels];
        });

        // Watch for registration status
        this.sipService.registrationStatus$.subscribe(status => {
            console.log('📞 SIP Registration status:', status);
            if (status === 'registered') {
                this.connectionStatus = 'CONNECTED';
            } else if (status === 'failed') {
                this.connectionStatus = 'DISCONNECTED';
            }
        });

        // Watch for incoming calls
        this.sipService.incomingCall$.subscribe(call => {
            if (call) {
                console.log('📲 Incoming call event:', call.number, 'My ext:', this.currentExtension);

                // Don't process calls FROM self
                if (call.number === this.currentExtension) {
                    console.log('⚠️ Ignoring call from self');
                    return;
                }

                // Just set state - dialpad opens when user clicks Accept
                this.incomingCall = call;
                console.log('📞 Incoming call popup should show for:', call.number);
            } else {
                this.incomingCall = null;
            }
        });
    }

    // Setup VK touch listener (like SmartX)
    private setupVkTouchListener(): void {
        document.addEventListener('touchend', (e: TouchEvent) => {
            const vkEl = document.getElementById('virtualKeyboard');
            if (vkEl && vkEl.contains(e.target as Node)) {
                let target = e.target as HTMLElement;

                // Handle nested elements - find kb-key or kb-close-icon
                if (!target.classList.contains('kb-key') && !target.classList.contains('kb-close-icon')) {
                    target = target.closest('.kb-key') as HTMLElement ||
                        target.closest('.kb-close-icon') as HTMLElement;
                }

                if (target) {
                    e.preventDefault();
                    e.stopPropagation();

                    // Dispatch proper MouseEvent for Angular compatibility
                    const clickEvent = new MouseEvent('click', {
                        bubbles: true,
                        cancelable: true,
                        view: window
                    });
                    target.dispatchEvent(clickEvent);
                    console.log('⌨️ VK touch dispatched click on:', target.textContent?.trim());
                }
            }
        }, { capture: true, passive: false });

        console.log('⌨️ VK touch listener setup');
    }

    // Setup PTT hotkey listener from Electron
    private setupPttListener(): void {
        // Check if running in Electron
        if ((window as any).electronAPI) {
            (window as any).electronAPI.onPttKeyDown((key: string) => {
                console.log('[PTT] Hotkey received:', key);
                this.togglePtt();
            });
            console.log('[PTT] Electron IPC listener registered');
        } else {
            console.log('[PTT] Not running in Electron, PTT hotkey disabled');
        }
    }

    // Toggle PTT state (for global hotkey)
    togglePtt(): void {
        this.pttActive = !this.pttActive;
        console.log('[PTT] Active:', this.pttActive);

        // Update target name based on selected channel
        if (this.pttActive && this.selectedChannel) {
            this.pttTargetName = this.selectedChannel.name || 'Unknown Channel';
        }
    }

    // Start PTT on mousedown (like SmartX)
    startPTT(event: MouseEvent, channel: Channel): void {
        // [FIX] Skip PTT if dragging from drag-handle
        if ((event.target as HTMLElement).closest('.drag-handle')) {
            return;
        }

        // Only allow PTT on active channels - for inactive, let click handle selection
        if (!channel.isActive) return;

        // Prevent click from triggering selection ONLY for PTT
        event.preventDefault();
        event.stopPropagation();

        // Mark that PTT was used (prevents selection toggle)
        this.pttJustFired = true;

        console.log('🎤 PTT ON:', channel.key);
        channel.isPtt = true;
        this.pttActive = true;
        this.pttTargetName = channel.name || 'Unknown Channel';
    }

    // Stop PTT on mouseup/mouseleave (like SmartX)
    stopPTT(channel: Channel): void {
        if (!channel.isPtt) return;

        console.log('🔇 PTT OFF:', channel.key);
        channel.isPtt = false;
        this.pttActive = false;
    }

    ngOnDestroy(): void {
        if (this.clockInterval) clearInterval(this.clockInterval);
    }

    private initChannels(): void {
        // Empty channels - no name means unassigned
        for (let i = 0; i < 16; i++) {
            this.channels.push({
                key: `ch-${i + 1}`,
                name: `Ch ${i + 1}`,   // Show Ch 1 - Ch 16
                extension: '',
                type: 'sip',
                position: i + 1,
                isActive: false,    // Not connected
                isCalling: false,   // Not calling
                isPtt: false,
                isSelected: false,
                volumeIn: 0,
                volumeOut: 0,
                groups: []
            });
        }
    }

    private initContacts(): void {
        // Load phonebook from CMS API
        // TODO: Get turret_user_id from logged in user
        const turretUserId = 1; // Default for now, should come from auth

        this.laravelAuth.getPhonebook(turretUserId).subscribe(entries => {
            if (entries.length > 0) {
                // Convert PhonebookEntry to Contact format
                this.contacts = entries.map(e => ({
                    id: String(e.id),
                    name: e.name,
                    phones: [e.phone] // Single phone per entry, can be enhanced
                }));
                this.filteredContacts = [...this.contacts];
                console.log('[Turret] Phonebook loaded from API:', this.contacts.length);
            } else {
                // Fallback to sample data if API returns empty
                console.log('[Turret] No phonebook entries, using sample data');
                this.contacts = [
                    { id: '1', name: 'Alice Smith', phones: ['021-1234567', '0812-1234567'] },
                    { id: '2', name: 'Bob Johnson', phones: ['021-2345678', '0813-2345678'] },
                    { id: '3', name: 'Charlie Brown', phones: ['021-3456789'] },
                    { id: '4', name: 'David Chen', phones: ['021-4567890', '0814-4567890'] },
                    { id: '5', name: 'Emily Davis', phones: ['021-5678901'] }
                ];
                this.filteredContacts = [...this.contacts];
            }
        });
    }

    /**
     * Load turret data from CMS API (Lines, VPW, CAS, Intercom, Extensions, Channel States, Config)
     */
    private loadTurretData(): void {
        console.log('[Turret] Loading data from CMS API...');

        // Load Lines
        this.laravelAuth.getLines().subscribe(lines => {
            this.lines = lines.map(l => ({
                id: String(l.id),
                name: l.name,
                use_ext: l.extension_number || l.use_ext || ''
            }));
            console.log('[Turret] Lines loaded:', this.lines.length);
        });

        // Load VPWs
        this.laravelAuth.getVPWs().subscribe(vpws => {
            this.vpwList = vpws.map(v => ({
                id: String(v.id),
                name: v.name,
                use_ext: v.extension_number || v.use_ext || ''
            }));
            console.log('[Turret] VPWs loaded:', this.vpwList.length);
        });

        // Load CAS
        this.laravelAuth.getCAS().subscribe(cas => {
            this.casList = cas.map(c => ({
                id: String(c.id),
                name: c.name,
                use_ext: c.extension_number || c.use_ext || ''
            }));
            console.log('[Turret] CAS loaded:', this.casList.length);
        });

        // Load Intercoms
        this.laravelAuth.getIntercoms().subscribe(intercoms => {
            this.intercomContacts = intercoms.map(i => ({
                name: i.name,
                ext: i.extension_number || i.ext || ''
            }));
            console.log('[Turret] Intercoms loaded:', this.intercomContacts.length);
        });

        // Load Extensions from API (no more hardcoded!)
        this.laravelAuth.getExtensionsList().subscribe(exts => {
            if (exts.length > 0) {
                this.extensions = exts;
                console.log('[Turret] Extensions loaded from API:', this.extensions.length);
            } else {
                console.log('[Turret] No extensions from API');
            }
        });

        // Load System Config (SIP server IP)
        this.laravelAuth.getSystemConfig().subscribe(config => {
            this.sipServer = config.sip_server;
            console.log('[Turret] System config loaded, SIP server:', this.sipServer);
        });

        // Load Channel States (persisted layout)
        this.laravelAuth.getTurretChannelStates(this.currentTurretUserId).subscribe(states => {
            if (states.length > 0) {
                console.log('[Turret] Channel states loaded:', states.length);
                states.forEach(state => {
                    const channel = this.channels.find(c => c.key === state.channel_key);
                    if (channel) {
                        channel.name = state.contact_name || channel.name;
                        channel.extension = state.extension || '';
                        channel.volumeIn = state.volume_in || 50;
                        channel.volumeOut = state.volume_out || 50;
                        channel.isPtt = state.is_ptt || false;
                        channel.groups = state.group_ids || [];
                        this.channelStateMap.set(state.channel_key, state.id!);
                    }
                });
                this.channels = [...this.channels];  // Trigger change detection
            }
        });
    }

    /**
     * Save channel state to database (call after channel is modified)
     */
    private saveChannelState(channel: Channel): void {
        const state: ChannelState = {
            id: this.channelStateMap.get(channel.key),
            turret_user_id: this.currentTurretUserId,
            channel_key: channel.key,
            contact_name: channel.name,
            extension: channel.extension,
            volume_in: channel.volumeIn,
            volume_out: channel.volumeOut,
            is_ptt: channel.isPtt,
            group_ids: channel.groups
        };

        this.laravelAuth.saveTurretChannelState(state).subscribe(saved => {
            if (saved) {
                console.log('[Turret] Channel state saved:', channel.key);
                if (!this.channelStateMap.has(channel.key) && saved.id) {
                    this.channelStateMap.set(channel.key, saved.id);
                }
            }
        });
    }

    private startClock(): void {
        this.updateClock();
        this.clockInterval = setInterval(() => this.updateClock(), 1000);
    }

    private updateClock(): void {
        const now = new Date();
        const months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
        this.currentDate = `${months[now.getMonth()]} ${now.getDate()} ${now.getFullYear()}`;
        this.currentTime = now.toLocaleTimeString('en-US', { hour12: true });
    }

    // === CHANNEL ACTIONS ===
    selectChannel(channel: Channel): void {
        // Skip selection if PTT was just used (prevents toggle on mouseup->click)
        if (this.pttJustFired) {
            this.pttJustFired = false;
            return;
        }
        this.channels.forEach(ch => ch.isSelected = false);
        channel.isSelected = true;
        this.selectedChannel = channel;
    }

    callChannel(): void {
        console.log('📞 callChannel called, selectedChannel:', this.selectedChannel?.key, 'name:', this.selectedChannel?.name, 'ext:', this.selectedChannel?.extension);

        if (this.selectedChannel && this.selectedChannel.name) {
            // Must have assigned contact to call
            if (!this.selectedChannel.extension) {
                console.log('⚠️ No phone number assigned to channel');
                return;
            }

            // Set calling state (yellow)
            const index = this.channels.findIndex(c => c.key === this.selectedChannel!.key);
            console.log('📞 Found channel at index:', index);

            if (index !== -1) {
                this.channels[index] = {
                    ...this.channels[index],
                    isCalling: true,
                    isSelected: true
                };
                this.channels = [...this.channels];
                this.selectedChannel = this.channels[index];
                console.log('📞 Calling:', this.selectedChannel.key, this.selectedChannel.extension, 'isCalling:', this.channels[index].isCalling);

                // [FIX] Make actual SIP call (using dynamic SIP server from config)
                const targetUri = `sip:${this.selectedChannel.extension}@${this.sipServer}`;
                this.sipService.makeCall(targetUri, this.selectedChannel.key);
            }
        } else {
            console.log('⚠️ No channel selected or channel has no name');
        }
    }


    hangupSelected(): void {
        if (this.selectedChannel) {
            const index = this.channels.findIndex(c => c.key === this.selectedChannel!.key);
            if (index !== -1) {
                // Reset all call states
                this.channels[index] = {
                    ...this.channels[index],
                    isActive: false,
                    isCalling: false,
                    isPtt: false
                };
                this.channels = [...this.channels];
                console.log('📴 Hangup channel:', this.selectedChannel.key);
            }
        }
    }

    // === CHANNEL DRAG & DROP ===
    onChannelDragStart(event: DragEvent, channel: Channel): void {
        this.draggedChannel = channel;
        if (event.dataTransfer) {
            event.dataTransfer.setData('channel', JSON.stringify({ key: channel.key, type: 'channel_move' }));
            event.dataTransfer.setData('channel-key', channel.key);
            event.dataTransfer.effectAllowed = 'move';
        }
        console.log('🔄 Channel drag start:', channel.key);
    }

    onChannelDragOver(event: DragEvent, channel: Channel): void {
        event.preventDefault();
        // Accept both 'copy' (from dialpad) and 'move' (from channel)
        if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
        this.dragOverChannel = channel.key;
    }

    onChannelDragLeave(event: DragEvent): void {
        this.dragOverChannel = null;
    }

    onChannelDrop(event: DragEvent, targetChannel: Channel): void {
        event.preventDefault();
        this.dragOverChannel = null;

        if (!event.dataTransfer) {
            this.draggedChannel = null;
            return;
        }

        // 1. Check for dialpad number drop
        const dialpadNumber = event.dataTransfer.getData('dialpad-number');
        if (dialpadNumber) {
            const existingChannel = this.channels.find(c => c.extension === dialpadNumber);
            if (existingChannel && existingChannel.key !== targetChannel.key) {
                console.log(`⚠️ Number ${dialpadNumber} already in ${existingChannel.key}`);
                return;
            }
            const contactName = event.dataTransfer.getData('contact-name');
            targetChannel.extension = dialpadNumber;
            targetChannel.name = contactName || dialpadNumber;

            // Check if this is from an active incoming call - link session and turn green
            if (this.activeIncomingSessionKey && this.activeIncomingNumber === dialpadNumber) {
                // Link the incoming session to this channel
                this.incomingSessionChannelMap.set(this.activeIncomingSessionKey, targetChannel.key);
                targetChannel.isActive = true;  // Turn channel GREEN
                targetChannel.isCalling = false;
                console.log(`✅ Linked incoming call to ${targetChannel.key} - CONNECTED (green)`);

                // Clear active incoming state
                this.activeIncomingSessionKey = null;
                this.activeIncomingNumber = null;
            }

            this.channels.forEach(ch => ch.isSelected = false);
            targetChannel.isSelected = true;
            this.selectedChannel = targetChannel;
            this.channels = [...this.channels];
            this.dialpadNumber = '';
            const dialpadDrawer = document.getElementById('dialpadDrawer');
            const phonebookDrawer = document.getElementById('phonebookDrawer');
            if (dialpadDrawer && bootstrap?.Offcanvas) bootstrap.Offcanvas.getInstance(dialpadDrawer)?.hide();
            if (phonebookDrawer && bootstrap?.Offcanvas) bootstrap.Offcanvas.getInstance(phonebookDrawer)?.hide();
            this.saveChannelState(targetChannel);  // Persist to DB
            this.draggedChannel = null;
            return;
        }

        // 2. Check for JSON data (line/vpw/cas, favourite, or channel_move)
        const jsonData = event.dataTransfer.getData('application/json') || event.dataTransfer.getData('channel');
        if (jsonData) {
            try {
                const data = JSON.parse(jsonData);

                // 2a. Line/VPW/CAS drop
                if (data.type === 'line_vpw_cas_item') {
                    const existingChannel = this.channels.find(c => c.extension === data.itemId);
                    if (existingChannel) {
                        console.log(`⚠️ Extension ${data.itemId} already in ${existingChannel.key}`);
                        return;
                    }
                    targetChannel.name = data.name;
                    targetChannel.extension = data.itemId;
                    this.channels.forEach(ch => ch.isSelected = false);
                    targetChannel.isSelected = true;
                    this.selectedChannel = targetChannel;
                    this.channels = [...this.channels];
                    ['lineListDrawer', 'vpwListDrawer', 'casListDrawer'].forEach(id => {
                        const drawer = document.getElementById(id);
                        if (drawer && bootstrap?.Offcanvas) bootstrap.Offcanvas.getInstance(drawer)?.hide();
                    });
                    this.saveChannelState(targetChannel);  // Persist to DB
                    this.draggedChannel = null;
                    return;
                }

                // 2b. Favourite item drop
                if (data.type === 'favourite_to_channel') {
                    const existingChannel = this.channels.find(c => c.name === data.name || c.extension === data.phone);
                    if (existingChannel && existingChannel.key !== targetChannel.key) {
                        this.duplicateModalMessage = `"${data.name}" already listed on Channel`;
                        this.showDuplicateModal = true;
                        return;
                    }
                    targetChannel.name = data.name;
                    targetChannel.extension = data.phone || '';
                    this.channels.forEach(ch => ch.isSelected = false);
                    targetChannel.isSelected = true;
                    this.selectedChannel = targetChannel;
                    this.channels = [...this.channels];
                    this.saveChannelState(targetChannel);  // Persist to DB
                    this.draggedChannel = null;
                    return;
                }

                // 2c. Channel-to-Channel MERGE drop
                if (data.type === 'channel_move' && data.key !== targetChannel.key) {
                    const sourceChannel = this.channels.find(c => c.key === data.key);
                    if (sourceChannel) {
                        console.log(`↔️ Merge/Move ${sourceChannel.key} to ${targetChannel.key}`);

                        // BIDIRECTIONAL MERGE: Result gets groups from BOTH source AND target
                        const mergedGroups = [...new Set([...targetChannel.groups, ...sourceChannel.groups])];

                        // Transfer data from source to target
                        targetChannel.extension = sourceChannel.extension;
                        targetChannel.name = sourceChannel.name;
                        targetChannel.isActive = sourceChannel.isActive;
                        targetChannel.groups = mergedGroups;  // Combined groups

                        console.log(`📦 Merged groups: ${mergedGroups.join(', ')}`);

                        // Clear Source
                        sourceChannel.extension = '';
                        sourceChannel.name = '';
                        sourceChannel.isActive = false;
                        sourceChannel.groups = [];

                        this.channels = [...this.channels];
                        this.saveChannelState(targetChannel);  // Persist to DB
                        this.saveChannelState(sourceChannel);  // Clear source in DB
                    }
                    this.draggedChannel = null;
                    return;
                }
            } catch (e) {
                console.log('Could not parse drag data');
            }
        }

        // 3. Check for recording drop
        const recordingId = event.dataTransfer.getData('recording-id');
        if (recordingId) {
            this.assignRecordingToChannel(targetChannel.key, recordingId);
            this.draggedChannel = null;
            return;
        }

        this.draggedChannel = null;
    }

    // === INCOMING CALL ===
    acceptCall(): void {
        if (this.incomingCall) {
            console.log('✅ Accepting call from:', this.incomingCall.number);

            // Answer the SIP session
            this.sipService.answerCall(this.incomingCall.channelKey);

            // Store the active incoming session key for later linking when user drags
            this.activeIncomingSessionKey = this.incomingCall.channelKey;
            this.activeIncomingNumber = this.incomingCall.number;

            // Set dialpad with incoming caller info
            this.dialpadNumber = this.incomingCall.number;
            this.dialpadCallerName = this.incomingCall.number;
            this.dialpadConnected = true;

            console.log('📞 Incoming call answered, drag dialpad to channel to assign');

            // Open dialpad drawer so user can drag the number
            const dialpadDrawer = document.getElementById('dialpadDrawer');
            if (dialpadDrawer && bootstrap?.Offcanvas) {
                new bootstrap.Offcanvas(dialpadDrawer).show();
            }

            // Clear incoming call popup
            this.incomingCall = null;
        }
    }

    rejectCall(): void {
        if (this.incomingCall) {
            console.log('❌ Rejecting call from:', this.incomingCall.number);
            // Terminate the SIP session
            this.sipService.hangupCall(this.incomingCall.channelKey);
            this.incomingCall = null;
        }
    }

    // === GROUP TALK ===
    toggleGroupMembership(channel: Channel, groupId: string): void {
        if (channel.groups.includes(groupId)) {
            // Remove from group
            channel.groups = channel.groups.filter(g => g !== groupId);
            console.log(`➖ Removed ${channel.name || channel.key} from ${groupId}`);
        } else {
            // Add to group
            channel.groups.push(groupId);
            console.log(`➕ Added ${channel.name || channel.key} to ${groupId}`);
        }
        this.channels = [...this.channels]; // Trigger change detection
    }

    onGroupTableDrop(event: DragEvent, group: Group): void {
        event.preventDefault();
        let channelKey = event.dataTransfer?.getData('channel-key');
        if (!channelKey) {
            const channelData = event.dataTransfer?.getData('channel');
            if (channelData) {
                try {
                    const parsed = JSON.parse(channelData);
                    channelKey = parsed.key;
                } catch (e) { }
            }
        }
        if (channelKey) {
            const channel = this.channels.find(c => c.key === channelKey);
            if (channel) {
                this.toggleGroupMembership(channel, group.id);
            }
        }
    }

    onGroupBtnDragOver(event: DragEvent, group: Group): void {
        event.preventDefault();
        event.stopPropagation();
        if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
        // Only log once per second to avoid spam
        if (!this._lastDragOverLog || Date.now() - this._lastDragOverLog > 1000) {
            console.log('🎯 DragOver on GBox:', group.id);
            this._lastDragOverLog = Date.now();
        }
    }
    private _lastDragOverLog = 0;

    onGroupBtnDrop(event: DragEvent, group: Group): void {
        event.preventDefault();
        console.log('📥 Group drop on:', group.id);

        let channelKey = event.dataTransfer?.getData('channel-key');
        console.log('  channel-key from dataTransfer:', channelKey);

        // Fallback: try to get from 'channel' data
        if (!channelKey) {
            const channelData = event.dataTransfer?.getData('channel');
            console.log('  channel data from dataTransfer:', channelData);
            if (channelData) {
                try {
                    const parsed = JSON.parse(channelData);
                    channelKey = parsed.key;
                    console.log('  parsed channel key:', channelKey);
                } catch (e) {
                    console.log('  failed to parse channel data');
                }
            }
        }

        if (channelKey) {
            const channel = this.channels.find(c => c.key === channelKey);
            if (channel) {
                this.toggleGroupMembership(channel, group.id);
            } else {
                console.log('  ⚠️ Channel not found:', channelKey);
            }
        } else {
            console.log('  ⚠️ No channel key in drop data');
        }
    }

    // === GROUP PTT ===
    startGroupPtt(group: Group): void {
        console.log('🎤 Group PTT ON:', group.id);
        group.isActive = true;

        // Find all channels in this group and activate PTT
        this.channels.forEach(channel => {
            if (channel.groups.includes(group.id) && channel.isActive) {
                // Channel is in group and has active call - unmute mic and show red indicator
                channel.isPtt = true;
                this.sipService.unmuteChannel(channel.key);
                console.log(`  📢 PTT ON for ${channel.key} (${channel.name})`);
            }
        });
        this.channels = [...this.channels]; // Trigger change detection

        // Also check incoming sessions mapped to channels
        this.incomingSessionChannelMap.forEach((channelKey, sessionKey) => {
            const channel = this.channels.find(c => c.key === channelKey);
            if (channel && channel.groups.includes(group.id) && channel.isActive) {
                this.sipService.unmuteChannel(sessionKey);
                console.log(`  📢 PTT ON for incoming ${sessionKey} -> ${channelKey}`);
            }
        });
    }

    stopGroupPtt(group: Group): void {
        console.log('🔇 Group PTT OFF:', group.id);
        group.isActive = false;

        // Find all channels in this group and deactivate PTT
        this.channels.forEach(channel => {
            if (channel.groups.includes(group.id) && channel.isActive) {
                // Channel is in group and has active call - mute mic and hide red indicator
                channel.isPtt = false;
                this.sipService.muteChannel(channel.key);
                console.log(`  🔇 PTT OFF for ${channel.key} (${channel.name})`);
            }
        });
        this.channels = [...this.channels]; // Trigger change detection

        // Also check incoming sessions
        this.incomingSessionChannelMap.forEach((channelKey, sessionKey) => {
            const channel = this.channels.find(c => c.key === channelKey);
            if (channel && channel.groups.includes(group.id) && channel.isActive) {
                this.sipService.muteChannel(sessionKey);
                console.log(`  🔇 PTT OFF for incoming ${sessionKey}`);
            }
        });
    }

    openTab(type: string, data?: any): void {
        console.log('Open tab:', type, data);
        if (type === 'grouptalk') {
            this.activeTabId = 'grouptalk';
        } else if (type === 'audio') {
            this.activeTabId = 'audio';
        } else if (type === 'info') {
            this.openPanel('info');
        }
    }

    // === DASHBOARD ===
    openPanel(panel: string): void {
        console.log('📂 Open panel:', panel);

        // Define panel type mapping
        const panelTypeMap: Record<string, { type: Tab['panelType'], title: string }> = {
            'grouptalk': { type: 'grouptalk', title: 'GROUP TALK' },
            'audio': { type: 'audio', title: 'AUDIO SETTINGS' },
            'recordings': { type: 'audiorec', title: 'AUDIO RECORDINGS' },
            'whatsapp': { type: 'whatsapp', title: 'WHATSAPP' },
            'teams': { type: 'teams', title: 'TEAMS' },
            'info': { type: 'info', title: 'INFORMATION' }
        };

        // Check if this is a known panel type
        const panelConfig = panelTypeMap[panel];
        if (panelConfig) {
            // Check if tab already exists
            let existingTab = this.tabs.find(t => t.panelType === panelConfig.type);

            if (existingTab) {
                // Switch to existing tab
                this.activeTabId = existingTab.id;
                console.log('🔄 Switched to existing tab:', existingTab.title);
            } else {
                // Create new tab (like addNewTab pattern)
                const newTab: Tab = {
                    id: `${panelConfig.type}-${Date.now()}`,
                    title: panelConfig.title,
                    isClosable: true,
                    panelType: panelConfig.type,
                    items: []  // Empty items for panel tabs (not FAV/dashboard)
                };
                this.tabs.push(newTab);
                this.activeTabId = newTab.id;
                console.log('🆕 Created new panel tab:', newTab.title);
            }
            return;
        }

        // Handle favourite panels - format: favourite_fav-xxx
        if (panel.startsWith('favourite_')) {
            const tabId = panel.replace('favourite_', '');

            // Check if tab already exists in tabs array
            const existingTab = this.tabs.find(t => t.id === tabId);
            if (existingTab) {
                // Just switch to it
                this.activeTabId = tabId;
                console.log('⭐ Switched to existing favourite tab:', tabId);
            } else {
                // Load from savedFavourites and create tab
                const savedFavourites = JSON.parse(localStorage.getItem('smartucx_saved_favourites') || '{}');
                const favData = savedFavourites[tabId];

                if (favData) {
                    // Create tab from saved data
                    const newTab: Tab = {
                        id: tabId,
                        title: favData.title || 'Favourite',
                        isClosable: true,
                        panelType: 'fav',
                        isEditMode: false,
                        items: favData.items || new Array(24).fill(null)
                    };
                    this.tabs.push(newTab);
                    this.activeTabId = tabId;
                    console.log('⭐ Loaded favourite tab from storage:', tabId);
                } else {
                    console.warn('Favourite not found in storage:', tabId);
                }
            }
        }
    }

    addItem(): void {
        // Find first empty slot
        const emptySlot = this.dashboardLayout.findIndex(slot => slot === null);
        if (emptySlot === -1) {
            console.log('No empty slots available');
            return;
        }

        // Create a new Favourite icon
        const favCount = this.dashboardLayout.filter(i => i?.id.startsWith('fav-')).length + 1;
        const newFav = {
            id: `fav-${Date.now()}`,
            label: `Favourite ${favCount}`,
            icon: 'star',
            color: '#ff4d4d',
            bgColor: 'rgba(255, 77, 77, 0.1)',
            panel: 'favourite',
            isDeletable: true
        };

        // Place in first empty slot
        if (this.activeTab) {
            this.activeTab.items[emptySlot] = newFav;
            this.tabs = [...this.tabs];  // Trigger change detection
        }
        console.log('Added new favourite:', newFav.id, 'at slot', emptySlot);
    }

    deleteItem(): void { console.log('Delete item'); }

    // Get count of items in a favourite tab (for dashboard badge)
    getFavItemCount(iconId: string): number {
        // iconId is like 'fav_xxx', we need to look up the tab or savedFavourites
        const tabId = iconId.replace('fav_', '');

        // Check in current tabs first
        const tab = this.tabs.find(t => t.id === tabId);
        if (tab && tab.items) {
            return tab.items.filter((item: any) => item !== null).length;
        }

        // Otherwise check in localStorage
        const savedFavourites = JSON.parse(localStorage.getItem('smartucx_saved_favourites') || '{}');
        const favData = savedFavourites[tabId];
        if (favData && favData.items) {
            return favData.items.filter((item: any) => item !== null).length;
        }

        return 0;
    }

    // === HEADER ===
    openSettings(): void {
        const drawer = document.getElementById('toolsDrawer');
        if (drawer && bootstrap?.Offcanvas) {
            new bootstrap.Offcanvas(drawer).show();
        }
    }

    openDialpad(): void {
        const drawer = document.getElementById('dialpadDrawer');
        if (drawer && bootstrap?.Offcanvas) {
            new bootstrap.Offcanvas(drawer).show();
        }
    }

    // === DRAWER: SETTINGS ===
    toggleSubmenu(menu: string): void {
        this.submenuOpen = this.submenuOpen === menu ? null : menu;
    }


    // === DRAWER: INTERCOM ===
    callIntercom(contact: { name: string; ext: string }): void {
        console.log('Call intercom:', contact.name);
    }

    // === DRAWER: PHONEBOOK ===
    filterPhonebook(): void {
        const q = this.phoneSearchQuery.toLowerCase();
        if (!q) {
            this.filteredContacts = [...this.contacts];
            return;
        }
        this.filteredContacts = this.contacts.filter(c =>
            c.name.toLowerCase().includes(q) ||
            c.phones.some(p => p.includes(q))
        );
    }

    scrollToLetter(letter: string, event?: Event): void {
        if (event) {
            event.preventDefault();
            event.stopPropagation();
        }

        // Find first contact starting with this letter
        const contact = this.filteredContacts.find(c =>
            c.name.toUpperCase().startsWith(letter)
        );
        if (contact) {
            const contactList = document.getElementById('contact-list-scroll');
            if (contactList) {
                const contactItems = contactList.querySelectorAll('.contact-card');
                const index = this.filteredContacts.indexOf(contact);
                if (contactItems && contactItems[index]) {
                    // Use relative scrolling to avoid scrolling the whole page
                    const item = contactItems[index] as HTMLElement;
                    const topPos = item.offsetTop - contactList.offsetTop;
                    contactList.scrollTo({ top: topPos, behavior: 'smooth' });
                }
            }
        }
    }

    callContact(contact: Contact): void {
        console.log('Call contact:', contact.name, contact.phones[0]);
    }

    toggleContactExpand(contact: Contact): void {
        contact.expanded = !contact.expanded;
    }

    dialPhone(phone: string): void {
        console.log('📞 Dialing phone:', phone);
        // Set dialpad number and open dialpad
        this.dialpadNumber = phone;
        const drawer = document.getElementById('dialpadDrawer');
        if (drawer && bootstrap?.Offcanvas) {
            new bootstrap.Offcanvas(drawer).show();
        }
    }

    handlePhoneDragStart(event: DragEvent, phone: string, contactName?: string): void {
        if (event.dataTransfer) {
            // Legacy format for channel drops
            event.dataTransfer.setData('text/plain', phone);
            event.dataTransfer.setData('dialpad-number', phone);
            if (contactName) {
                event.dataTransfer.setData('contact-name', contactName);
            }

            // JSON format for favourite drops (phonebook type)
            const dragData = JSON.stringify({
                type: 'phonebook',
                id: `contact_${Date.now()}`,
                name: contactName || 'Unknown',
                phone: phone
            });
            event.dataTransfer.setData('application/json', dragData);

            event.dataTransfer.effectAllowed = 'copy';
            console.log('📞 Dragging phone:', phone, 'Contact:', contactName);
        }
    }

    // Touch drag state
    private touchDragData: { phone: string; contactName: string; startX: number; startY: number; isDragging: boolean; clone?: HTMLElement } | null = null;

    handlePhoneTouchStart(event: TouchEvent, phone: string, contactName: string): void {
        const touch = event.touches[0];
        this.touchDragData = {
            phone,
            contactName,
            startX: touch.clientX,
            startY: touch.clientY,
            isDragging: false
        };
        console.log('Touch start:', phone, contactName);
    }

    handlePhoneTouchMove(event: TouchEvent): void {
        if (!this.touchDragData) return;

        const touch = event.touches[0];
        const deltaX = Math.abs(touch.clientX - this.touchDragData.startX);
        const deltaY = Math.abs(touch.clientY - this.touchDragData.startY);

        // Start dragging if moved beyond threshold
        if (!this.touchDragData.isDragging && (deltaX > 10 || deltaY > 10)) {
            this.touchDragData.isDragging = true;
            event.preventDefault();

            // Create visual drag clone
            const clone = document.createElement('div');
            clone.className = 'touch-drag-clone';
            clone.textContent = this.touchDragData.contactName;
            clone.style.cssText = `
                position: fixed;
                z-index: 9999;
                background: var(--color-accent-green);
                color: #000;
                padding: 8px 16px;
                border-radius: 8px;
                font-weight: bold;
                pointer-events: none;
                transform: translate(-50%, -50%);
                left: ${touch.clientX}px;
                top: ${touch.clientY}px;
            `;
            document.body.appendChild(clone);
            this.touchDragData.clone = clone;
            console.log('Touch drag started:', this.touchDragData.contactName);
        }

        if (this.touchDragData.isDragging && this.touchDragData.clone) {
            event.preventDefault();
            // Move clone with touch
            this.touchDragData.clone.style.left = `${touch.clientX}px`;
            this.touchDragData.clone.style.top = `${touch.clientY}px`;

            // Highlight potential drop targets (channels AND favourite slots)
            const elements = document.elementsFromPoint(touch.clientX, touch.clientY);
            const channelCell = elements.find(el => el.classList.contains('call-cell'));
            const favSlot = elements.find(el => el.classList.contains('favourite-item') && el.classList.contains('empty-slot'));

            document.querySelectorAll('.call-cell, .favourite-item.empty-slot').forEach(cell => cell.classList.remove('drag-over'));
            if (channelCell) {
                channelCell.classList.add('drag-over');
            }
            if (favSlot) {
                favSlot.classList.add('drag-over');
            }
        }
    }

    handlePhoneTouchEnd(event: TouchEvent): void {
        if (!this.touchDragData) return;

        // Remove clone
        if (this.touchDragData.clone) {
            this.touchDragData.clone.remove();
        }

        if (this.touchDragData.isDragging) {
            // Find drop target
            const touch = event.changedTouches[0];
            const elements = document.elementsFromPoint(touch.clientX, touch.clientY);
            const channelCell = elements.find(el => el.classList.contains('call-cell')) as HTMLElement;
            const favSlot = elements.find(el => el.classList.contains('favourite-item') && el.classList.contains('empty-slot')) as HTMLElement;

            // Handle drop on channel
            if (channelCell) {
                const channelKey = channelCell.dataset['channelKey'];
                const targetChannel = this.channels.find(c => c.key === channelKey);

                if (targetChannel) {
                    // Check for duplicate
                    const existingChannel = this.channels.find(c => c.extension === this.touchDragData!.phone);
                    if (existingChannel) {
                        console.log(`⚠️ Number already in ${existingChannel.key}`);
                    } else {
                        // Assign to channel (not active yet - need to CALL)
                        console.log(`📞 Touch drop ${this.touchDragData.contactName} to ${channelKey}`);
                        targetChannel.extension = this.touchDragData.phone;
                        targetChannel.name = this.touchDragData.contactName;
                        // Don't set isActive - need to call first

                        // [FIX] Auto-select channel after drop
                        this.channels.forEach(ch => ch.isSelected = false);
                        targetChannel.isSelected = true;
                        this.selectedChannel = targetChannel;

                        this.channels = [...this.channels];

                        // Close phonebook drawer
                        const drawer = document.getElementById('phonebookDrawer');
                        if (drawer && bootstrap?.Offcanvas) {
                            bootstrap.Offcanvas.getInstance(drawer)?.hide();
                        }
                    }
                }
            }
            // Handle drop on favourite slot
            else if (favSlot && this.activeTab && this.activeTabId !== 'dashboard') {
                const slotIndex = parseInt(favSlot.dataset['index'] || '-1');
                if (slotIndex >= 0 && slotIndex < 24) {
                    const newItem = {
                        id: `contact_${Date.now()}`,
                        label: this.touchDragData.contactName,
                        icon: 'contact_page',
                        color: 'var(--color-accent-green)',
                        bgColor: '#333',
                        isDeletable: true
                    };

                    // Check for duplicates
                    const isDuplicate = this.activeTab.items.some((item: any) => item?.label === newItem.label);
                    if (!isDuplicate) {
                        this.activeTab.items[slotIndex] = newItem;
                        this.tabs = [...this.tabs];
                        console.log(`⭐ Touch drop ${this.touchDragData.contactName} to favourite slot ${slotIndex}`);

                        // Close phonebook drawer
                        const drawer = document.getElementById('phonebookDrawer');
                        if (drawer && bootstrap?.Offcanvas) {
                            bootstrap.Offcanvas.getInstance(drawer)?.hide();
                        }
                    } else {
                        console.log('⚠️ Contact already in favourite');
                    }
                }
            }

            // Clear drag-over styling
            document.querySelectorAll('.call-cell, .favourite-item.empty-slot').forEach(cell => cell.classList.remove('drag-over'));
        }

        this.touchDragData = null;
    }

    // === DRAWER: DIALPAD ===
    dialNum(num: string): void {
        this.dialpadNumber += num;
    }

    clearDialpad(): void {
        this.dialpadNumber = '';
        this.dialpadContactName = '';
    }

    deleteLastDigit(): void {
        if (this.dialpadNumber.length > 0) {
            this.dialpadNumber = this.dialpadNumber.slice(0, -1);
        }
    }

    dialFromPad(): void {
        if (this.dialpadNumber) {
            console.log('Dialing:', this.dialpadNumber);
            this.dialpadConnected = true;
        }
    }

    hangupDialpad(): void {
        this.dialpadConnected = false;
        this.dialpadNumber = '';
    }

    startDialpadPTT(): void {
        this.audioService.startPtt();
    }

    stopDialpadPTT(): void {
        this.audioService.stopPtt();
    }

    // Handle drag from dialpad display to channel cells
    handleDialDragStart(event: DragEvent): void {
        if (this.dialpadNumber && event.dataTransfer) {
            event.dataTransfer.setData('text/plain', this.dialpadNumber);
            event.dataTransfer.setData('dialpad-number', this.dialpadNumber);
            event.dataTransfer.effectAllowed = 'copy';
            console.log('Dragging dialpad number:', this.dialpadNumber);
        }
    }

    // Touch drag for dialpad
    dialpadDragClone: HTMLElement | null = null;

    handleDialTouchStart(event: TouchEvent): void {
        if (!this.dialpadNumber) return;
        event.preventDefault();

        const touch = event.touches[0];
        const clone = document.createElement('div');
        clone.className = 'drag-clone';
        clone.innerHTML = `📞 ${this.dialpadNumber}`;
        clone.style.cssText = `
            position: fixed;
            left: ${touch.clientX - 30}px;
            top: ${touch.clientY - 20}px;
            background: #00ff66;
            padding: 8px 12px;
            border-radius: 4px;
            color: black;
            z-index: 9999;
            pointer-events: none;
            font-size: 14px;
            font-weight: bold;
        `;
        document.body.appendChild(clone);
        this.dialpadDragClone = clone;
        console.log('📱 Dialpad touch drag start:', this.dialpadNumber);
    }

    handleDialTouchMove(event: TouchEvent): void {
        if (!this.dialpadDragClone) return;
        event.preventDefault();
        const touch = event.touches[0];
        this.dialpadDragClone.style.left = `${touch.clientX - 30}px`;
        this.dialpadDragClone.style.top = `${touch.clientY - 20}px`;
    }

    handleDialTouchEnd(event: TouchEvent): void {
        if (!this.dialpadDragClone) return;

        // Remove clone
        this.dialpadDragClone.remove();
        this.dialpadDragClone = null;

        // Find what we dropped on
        const touch = event.changedTouches[0];
        const elements = document.elementsFromPoint(touch.clientX, touch.clientY);
        const channelCell = elements.find(el => el.classList.contains('call-cell'));

        if (channelCell) {
            const channelKey = channelCell.getAttribute('data-channel-key');
            if (channelKey) {
                const targetChannel = this.channels.find(c => c.key === channelKey);
                if (targetChannel) {
                    console.log('📱 Dialpad touch drop on:', channelKey);

                    // Same logic as onChannelDrop for dialpad
                    const existingChannel = this.channels.find(c => c.extension === this.dialpadNumber && c.key !== channelKey);
                    if (existingChannel) {
                        console.log(`⚠️ Number ${this.dialpadNumber} already in ${existingChannel.key}`);
                        return;
                    }

                    targetChannel.extension = this.dialpadNumber;
                    targetChannel.name = this.dialpadCallerName || this.dialpadNumber;

                    // Check if this is from an active incoming call
                    if (this.activeIncomingSessionKey && this.activeIncomingNumber === this.dialpadNumber) {
                        this.incomingSessionChannelMap.set(this.activeIncomingSessionKey, targetChannel.key);
                        targetChannel.isActive = true;
                        targetChannel.isCalling = false;
                        console.log(`✅ Linked incoming call to ${targetChannel.key} - CONNECTED (green)`);
                        this.activeIncomingSessionKey = null;
                        this.activeIncomingNumber = null;
                    }

                    this.channels.forEach(ch => ch.isSelected = false);
                    targetChannel.isSelected = true;
                    this.selectedChannel = targetChannel;
                    this.channels = [...this.channels];
                    this.dialpadNumber = '';

                    // Close dialpad
                    const dialpadDrawer = document.getElementById('dialpadDrawer');
                    if (dialpadDrawer && bootstrap?.Offcanvas) {
                        bootstrap.Offcanvas.getInstance(dialpadDrawer)?.hide();
                    }
                }
            }
        }
    }

    // [NEW] Open dialpad with pre-filled number (double-click on Line item)
    openDialpadWithNumber(number: string, name: string): void {
        console.log('📞 Opening dialpad with:', number, name);
        this.dialpadNumber = number;
        this.dialpadContactName = name;

        // Close line drawer first
        const lineDrawer = document.getElementById('lineListDrawer');
        if (lineDrawer && bootstrap?.Offcanvas) {
            bootstrap.Offcanvas.getInstance(lineDrawer)?.hide();
        }

        // Open dialpad drawer
        setTimeout(() => {
            const dialpadDrawer = document.getElementById('dialpadDrawer');
            if (dialpadDrawer && bootstrap?.Offcanvas) {
                const offcanvas = new bootstrap.Offcanvas(dialpadDrawer);
                offcanvas.show();
            }
        }, 200);
    }

    // ============================================
    // DRAG HANDLE: Channel Drag to Hangup/Delete
    // ============================================
    dragHandleChannel: Channel | null = null;
    dragHandleClone: HTMLElement | null = null;

    onDragHandleStart(event: DragEvent, channel: Channel): void {
        this.dragHandleChannel = channel;
        if (event.dataTransfer) {
            event.dataTransfer.setData('channel-key', channel.key);
            event.dataTransfer.effectAllowed = 'move';
        }
        console.log('🔧 Drag handle start:', channel.key);

        // Track mouse position during drag for later detection
        document.addEventListener('dragover', this._trackDragPosition, true);
    }

    private _lastDragX = 0;
    private _lastDragY = 0;
    private _trackDragPosition = (e: DragEvent) => {
        this._lastDragX = e.clientX;
        this._lastDragY = e.clientY;
    };

    onDragHandleEnd(event: DragEvent, channel: Channel): void {
        // Remove position tracker
        document.removeEventListener('dragover', this._trackDragPosition, true);

        // Use last known position to detect drop target
        const elements = document.elementsFromPoint(this._lastDragX, this._lastDragY);
        const groupBtn = elements.find(el => el.classList.contains('group-btn'));
        const channelCell = elements.find(el => el.classList.contains('call-cell'));

        if (groupBtn && this.dragHandleChannel) {
            // Drop on GBox - toggle group membership
            const titleEl = groupBtn.querySelector('.group-title');
            const groupId = titleEl?.textContent?.trim() || '';
            if (groupId && ['G1', 'G2', 'G3'].includes(groupId)) {
                console.log('📥 Mouse drag end on GBox:', groupId);
                this.toggleGroupMembership(this.dragHandleChannel, groupId);
            }
        } else if (channelCell && this.dragHandleChannel) {
            // Drop on another channel - merge/move
            const targetKey = channelCell.getAttribute('data-channel-key');
            if (targetKey && targetKey !== this.dragHandleChannel.key) {
                const targetChannel = this.channels.find(c => c.key === targetKey);
                if (targetChannel) {
                    console.log(`↔️ Mouse Merge/Move ${this.dragHandleChannel.key} to ${targetKey}`);

                    // BIDIRECTIONAL MERGE: Result gets groups from BOTH source AND target
                    const mergedGroups = [...new Set([...targetChannel.groups, ...this.dragHandleChannel.groups])];

                    // Transfer data from source to target
                    targetChannel.extension = this.dragHandleChannel.extension;
                    targetChannel.name = this.dragHandleChannel.name;
                    targetChannel.isActive = this.dragHandleChannel.isActive;
                    targetChannel.groups = mergedGroups;

                    console.log(`📦 Merged groups: ${mergedGroups.join(', ') || 'none'}`);

                    // Clear Source channel completely
                    this.dragHandleChannel.extension = '';
                    this.dragHandleChannel.name = '';
                    this.dragHandleChannel.isActive = false;
                    this.dragHandleChannel.isSelected = false;
                    this.dragHandleChannel.groups = [];

                    // Select target channel
                    this.channels.forEach(ch => ch.isSelected = false);
                    targetChannel.isSelected = true;
                    this.selectedChannel = targetChannel;

                    this.channels = [...this.channels];
                }
            }
        }

        this.dragHandleChannel = null;
        console.log('🔧 Drag handle end:', channel.key);
    }

    onDragHandleTouchStart(event: TouchEvent, channel: Channel): void {
        event.preventDefault();
        event.stopPropagation();

        this.dragHandleChannel = channel;

        // Create visual clone
        const touch = event.touches[0];
        const clone = document.createElement('div');
        clone.className = 'drag-clone';
        clone.innerHTML = `<span class="material-symbols-sharp">drag_indicator</span> ${channel.name}`;
        clone.style.cssText = `
            position: fixed;
            left: ${touch.clientX - 30}px;
            top: ${touch.clientY - 20}px;
            background: #333;
            padding: 8px 12px;
            border-radius: 4px;
            color: white;
            z-index: 9999;
            pointer-events: none;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        `;
        document.body.appendChild(clone);
        this.dragHandleClone = clone;

        console.log('🔧 Drag handle touch start:', channel.key);
    }

    onDragHandleTouchMove(event: TouchEvent): void {
        if (!this.dragHandleChannel || !this.dragHandleClone) return;

        event.preventDefault();
        const touch = event.touches[0];
        this.dragHandleClone.style.left = `${touch.clientX - 30}px`;
        this.dragHandleClone.style.top = `${touch.clientY - 20}px`;

        // Highlight action buttons on hover
        const elements = document.elementsFromPoint(touch.clientX, touch.clientY);
        const hangupBtn = elements.find(el => el.classList.contains('hangup-btn'));
        const trashBtn = elements.find(el => el.classList.contains('trash-btn'));

        // Reset highlights
        document.querySelectorAll('.channel-action-btn').forEach(btn => btn.classList.remove('drag-over'));

        if (hangupBtn) {
            hangupBtn.classList.add('drag-over');
            this.dragOverActionBtn = 'hangup';
        } else if (trashBtn) {
            trashBtn.classList.add('drag-over');
            this.dragOverActionBtn = 'trash';
        } else {
            this.dragOverActionBtn = null;
        }
    }

    onDragHandleTouchEnd(event: TouchEvent): void {
        if (!this.dragHandleChannel) return;

        // Remove clone
        if (this.dragHandleClone) {
            this.dragHandleClone.remove();
            this.dragHandleClone = null;
        }

        // Check drop target
        const touch = event.changedTouches[0];
        const elements = document.elementsFromPoint(touch.clientX, touch.clientY);
        const hangupBtn = elements.find(el => el.classList.contains('hangup-btn'));
        const trashBtn = elements.find(el => el.classList.contains('trash-btn'));
        const groupBtn = elements.find(el => el.classList.contains('group-btn'));

        if (hangupBtn) {
            console.log('📴 Drag hangup:', this.dragHandleChannel.key);
            this.hangupChannel(this.dragHandleChannel);
        } else if (trashBtn) {
            console.log('🗑️ Drag delete:', this.dragHandleChannel.key);
            this.deleteChannel(this.dragHandleChannel);
        } else if (groupBtn) {
            // Find the group ID from the group button's title element
            const titleEl = groupBtn.querySelector('.group-title');
            const groupId = titleEl?.textContent?.trim() || '';
            if (groupId && ['G1', 'G2', 'G3'].includes(groupId)) {
                const group = this.groups.find(g => g.id === groupId);
                if (group) {
                    console.log('📥 Touch drop on GBox:', groupId);
                    this.toggleGroupMembership(this.dragHandleChannel, groupId);
                }
            }
        }

        // Reset
        this.dragHandleChannel = null;
        this.dragOverActionBtn = null;
        document.querySelectorAll('.channel-action-btn').forEach(btn => btn.classList.remove('drag-over'));
    }

    // Hangup specific channel
    hangupChannel(channel: Channel): void {
        const index = this.channels.findIndex(c => c.key === channel.key);
        if (index !== -1) {
            this.sipService.hangupCall(channel.key);
            this.channels[index] = {
                ...this.channels[index],
                isActive: false,
                isCalling: false,
                isPtt: false
            };
            this.channels = [...this.channels];
            console.log('📴 Hangup channel:', channel.key);
        }
    }

    // Delete/clear channel assignment
    deleteChannel(channel: Channel): void {
        const index = this.channels.findIndex(c => c.key === channel.key);
        if (index !== -1) {
            // Hangup first if active
            if (channel.isActive || channel.isCalling) {
                this.sipService.hangupCall(channel.key);
            }
            // Clear assignment
            this.channels[index] = {
                ...this.channels[index],
                name: '',
                extension: '',
                isActive: false,
                isCalling: false,
                isPtt: false
            };
            this.channels = [...this.channels];
            console.log('🗑️ Deleted channel:', channel.key);
        }
    }

    // ============================================
    // DRAG & DROP: LINE/VPW/CAS ITEMS
    // ============================================
    handleLineVPWCASDragStart(event: DragEvent, itemName: string, itemType: string, itemId: string): void {
        const dragData = JSON.stringify({
            type: 'line_vpw_cas_item',
            name: itemName,
            itemType: itemType,
            itemId: itemId
        });

        if (event.dataTransfer) {
            event.dataTransfer.setData('application/json', dragData);
            event.dataTransfer.setData('text/plain', dragData);
            event.dataTransfer.effectAllowed = 'copy';
        }
        console.log(`📦 Dragging ${itemType}: ${itemName}`);
    }

    // Touch drag for Line/VPW/CAS items
    handleDrawerTouchStart(event: TouchEvent, itemName: string, itemType: string, itemId: string): void {
        const touch = event.touches[0];
        const target = event.currentTarget as HTMLElement;

        this.touchDragData = {
            contactName: itemName,
            phone: itemId, // Use itemId as identifier
            startX: touch.clientX,
            startY: touch.clientY,
            isDragging: false,
            clone: undefined
        };

        // Store itemType for later use
        (this.touchDragData as any).itemType = itemType;
    }

    handleDrawerTouchMove(event: TouchEvent): void {
        if (!this.touchDragData) return;

        const touch = event.touches[0];
        const deltaX = Math.abs(touch.clientX - this.touchDragData.startX);
        const deltaY = Math.abs(touch.clientY - this.touchDragData.startY);

        // Start drag if moved more than 10px
        if (!this.touchDragData.isDragging && (deltaX > 10 || deltaY > 10)) {
            this.touchDragData.isDragging = true;

            // Create clone
            const clone = document.createElement('div');
            clone.className = 'touch-drag-clone';
            clone.textContent = this.touchDragData.contactName;
            clone.style.cssText = `
                position: fixed;
                left: ${touch.clientX}px;
                top: ${touch.clientY}px;
                transform: translate(-50%, -50%);
                background: var(--color-accent-green);
                color: white;
                padding: 8px 16px;
                border-radius: 8px;
                z-index: 9999;
                pointer-events: none;
                font-size: 14px;
            `;
            document.body.appendChild(clone);
            this.touchDragData.clone = clone;
        }

        // Move clone
        if (this.touchDragData.isDragging && this.touchDragData.clone) {
            this.touchDragData.clone.style.left = `${touch.clientX}px`;
            this.touchDragData.clone.style.top = `${touch.clientY}px`;

            // Highlight drop targets (channel cells)
            document.querySelectorAll('.call-cell').forEach(cell => {
                const rect = cell.getBoundingClientRect();
                if (touch.clientX >= rect.left && touch.clientX <= rect.right &&
                    touch.clientY >= rect.top && touch.clientY <= rect.bottom) {
                    cell.classList.add('drag-over');
                } else {
                    cell.classList.remove('drag-over');
                }
            });
        }

        event.preventDefault();
    }

    handleDrawerTouchEnd(event: TouchEvent): void {
        if (!this.touchDragData) return;

        // Remove clone
        if (this.touchDragData.clone) {
            this.touchDragData.clone.remove();
        }

        if (this.touchDragData.isDragging) {
            const touch = event.changedTouches[0];
            const elements = document.elementsFromPoint(touch.clientX, touch.clientY);
            const channelCell = elements.find(el => el.classList.contains('call-cell')) as HTMLElement;

            if (channelCell) {
                const channelKey = channelCell.dataset['channelKey'];
                const targetChannel = this.channels.find(c => c.key === channelKey);

                if (targetChannel) {
                    console.log(`📞 Touch drop ${this.touchDragData.contactName} to ${channelKey}`);
                    targetChannel.name = this.touchDragData.contactName;
                    targetChannel.extension = this.touchDragData.phone;

                    // [FIX] Auto-select channel after drop
                    this.channels.forEach(ch => ch.isSelected = false);
                    targetChannel.isSelected = true;
                    this.selectedChannel = targetChannel;

                    this.channels = [...this.channels];

                    // Close drawer
                    const lineDrawer = document.getElementById('lineListDrawer');
                    const vpwDrawer = document.getElementById('vpwListDrawer');
                    const casDrawer = document.getElementById('casListDrawer');
                    [lineDrawer, vpwDrawer, casDrawer].forEach(drawer => {
                        if (drawer && bootstrap?.Offcanvas) {
                            bootstrap.Offcanvas.getInstance(drawer)?.hide();
                        }
                    });
                }
            }

            // Clear drag-over styling
            document.querySelectorAll('.call-cell').forEach(cell => cell.classList.remove('drag-over'));
        }

        this.touchDragData = null;
    }


    // ============================================
    // DRAG & DROP: DASHBOARD SLOTS (24-slot layout)
    // ============================================
    draggedSlotIndex: number | null = null;
    dragOverSlotIndex: number | null = null;

    onSlotDragStart(event: DragEvent, slotIndex: number): void {
        this.draggedSlotIndex = slotIndex;
        const icon = this.dashboardLayout[slotIndex];
        if (event.dataTransfer && icon) {
            event.dataTransfer.setData('text/plain', String(slotIndex));
            event.dataTransfer.setData('application/json', JSON.stringify({
                type: 'dashboard_slot',
                slotIndex: slotIndex,
                iconId: icon.id
            }));
            event.dataTransfer.effectAllowed = 'move';
        }
        // Visual feedback
        (event.target as HTMLElement).closest('.dashboard-icon-item')?.classList.add('dragging');
        console.log('Drag start slot:', slotIndex, icon?.id);
    }

    onSlotDragEnd(event: DragEvent): void {
        // Cleanup all drag states
        document.querySelectorAll('.dashboard-icon-item.dragging').forEach(el => el.classList.remove('dragging'));
        document.querySelectorAll('.dashboard-icon-item.drag-over').forEach(el => el.classList.remove('drag-over'));
        document.querySelectorAll('.dashboard-empty-cell.drag-over').forEach(el => el.classList.remove('drag-over'));
        this.draggedSlotIndex = null;
        this.dragOverSlotIndex = null;
    }

    onSlotDragOver(event: DragEvent, slotIndex: number): void {
        event.preventDefault();
        if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';

        // Visual feedback on target slot
        if (this.dragOverSlotIndex !== slotIndex) {
            document.querySelectorAll('.dashboard-icon-item.drag-over').forEach(el => el.classList.remove('drag-over'));
            document.querySelectorAll('.dashboard-empty-cell.drag-over').forEach(el => el.classList.remove('drag-over'));
            const target = (event.target as HTMLElement).closest('.dashboard-icon-item, .dashboard-empty-cell');
            target?.classList.add('drag-over');
            this.dragOverSlotIndex = slotIndex;
        }
    }

    onSlotDragLeave(event: DragEvent): void {
        const target = (event.target as HTMLElement).closest('.dashboard-icon-item, .dashboard-empty-cell');
        target?.classList.remove('drag-over');
    }

    onSlotDrop(event: DragEvent, targetSlotIndex: number): void {
        event.preventDefault();

        // Cleanup visual states
        document.querySelectorAll('.dashboard-icon-item.dragging').forEach(el => el.classList.remove('dragging'));
        document.querySelectorAll('.dashboard-icon-item.drag-over').forEach(el => el.classList.remove('drag-over'));
        document.querySelectorAll('.dashboard-empty-cell.drag-over').forEach(el => el.classList.remove('drag-over'));

        if (this.draggedSlotIndex !== null && this.draggedSlotIndex !== targetSlotIndex) {
            // SWAP slots - move icon from source to target
            const sourceIcon = this.dashboardLayout[this.draggedSlotIndex];
            const targetIcon = this.dashboardLayout[targetSlotIndex];

            // Swap contents
            if (this.activeTab) {
                this.activeTab.items[targetSlotIndex] = sourceIcon;
                this.activeTab.items[this.draggedSlotIndex] = targetIcon;
                this.tabs = [...this.tabs];  // Trigger change detection
            }

            console.log(`Swapped slot ${this.draggedSlotIndex} with slot ${targetSlotIndex}`);
        }

        this.draggedSlotIndex = null;
        this.dragOverSlotIndex = null;
    }

    // ============================================
    // DRAG & DROP: TRASH
    // ============================================
    onTrashDragOver(event: DragEvent): void {
        event.preventDefault();
        this.dragOverTrash = true;
    }

    onTrashDragLeave(event: DragEvent): void {
        this.dragOverTrash = false;
    }

    onTrashDrop(event: DragEvent): void {
        event.preventDefault();
        this.dragOverTrash = false;

        // Delete dragged channel
        if (this.draggedChannel) {
            const index = this.channels.findIndex(c => c.key === this.draggedChannel!.key);
            if (index !== -1) {
                this.channels[index] = {
                    ...this.channels[index],
                    name: `Ch ${index + 1}`,
                    extension: '',
                    isActive: false,
                    groups: []
                };
                console.log('Deleted channel:', this.draggedChannel.key);
            }
            this.draggedChannel = null;
        }

        // Handle fav_item_reorder drop (from favourite grid in edit mode)
        try {
            const jsonData = event.dataTransfer?.getData('application/json');
            if (jsonData) {
                const data = JSON.parse(jsonData);
                if (data.type === 'fav_item_reorder' && this.activeTab) {
                    const sourceIndex = data.sourceIndex;
                    if (sourceIndex !== null && sourceIndex !== undefined) {
                        const item = this.activeTab.items[sourceIndex];
                        if (item) {
                            this.activeTab.items[sourceIndex] = null;
                            this.tabs = [...this.tabs];
                            console.log('🗑️ Deleted fav item:', item.label, 'from slot', sourceIndex);
                            this.draggedFavIndex = null;
                            return;
                        }
                    }
                }
            }
        } catch (e) {
            console.log('Could not parse drop data');
        }

        // Delete dragged dashboard icon (only if deletable - favourites only)
        if (this.draggedSlotIndex !== null && this.activeTab) {
            const icon = this.activeTab.items[this.draggedSlotIndex];
            if (icon && icon.isDeletable) {
                this.activeTab.items[this.draggedSlotIndex] = null;
                this.tabs = [...this.tabs];  // Trigger change detection
                console.log('Deleted icon:', icon.id, 'from slot', this.draggedSlotIndex);
            } else if (icon) {
                console.log('Cannot delete core icon:', icon.id);
            }
            this.draggedSlotIndex = null;
        }
    }

    // ============================================
    // FAVOURITE SLOT DRAG & DROP (From Line/VPW/CAS/Phonebook)
    // ============================================
    onFavouriteSlotDragOver(event: DragEvent, slotIndex: number): void {
        event.preventDefault();
        this.dragOverEmptyCell = slotIndex;
        (event.target as HTMLElement)?.classList.add('drag-over');
    }

    onFavouriteSlotDrop(event: DragEvent, slotIndex: number): void {
        event.preventDefault();
        this.dragOverEmptyCell = null;
        (event.target as HTMLElement)?.classList.remove('drag-over');

        if (!this.activeTab || this.activeTabId === 'dashboard') return;

        try {
            const jsonData = event.dataTransfer?.getData('application/json') || event.dataTransfer?.getData('text/plain');
            if (!jsonData) return;

            const data = JSON.parse(jsonData);
            console.log('📥 Favourite Drop:', data);

            let newItem: DashboardIcon | null = null;

            // Handle fav item reorder (move to empty slot)
            if (data.type === 'fav_item_reorder') {
                const sourceIndex = data.sourceIndex;
                if (sourceIndex !== null && sourceIndex !== slotIndex) {
                    const sourceItem = this.activeTab.items[sourceIndex];
                    if (sourceItem) {
                        this.activeTab.items[slotIndex] = sourceItem;
                        this.activeTab.items[sourceIndex] = null;
                        this.tabs = [...this.tabs];
                        console.log(`✅ Moved item from ${sourceIndex} to empty slot ${slotIndex}`);
                        this.draggedFavIndex = null;
                    }
                }
                return;
            }

            // Handle Line/VPW/CAS drops
            if (data.type === 'line_vpw_cas_item') {
                let icon = 'call';
                let color = 'var(--color-accent-green)';

                if (data.itemType === 'line') {
                    icon = 'call';
                    color = 'var(--color-accent-green)';
                } else if (data.itemType === 'vpw') {
                    icon = 'private_connectivity';
                    color = 'var(--color-accent-red)';
                } else if (data.itemType === 'cas') {
                    icon = 'campaign';
                    color = 'var(--color-accent-blue)';
                }

                newItem = {
                    id: `${data.itemType}_${data.itemId}`,
                    label: data.name,
                    icon: icon,
                    color: color,
                    bgColor: '#333',
                    isDeletable: true
                };
            }
            // Handle Phonebook contact drops
            else if (data.type === 'phonebook') {
                newItem = {
                    id: `contact_${data.id}`,
                    label: data.name,
                    icon: 'contact_page',
                    color: 'var(--color-accent-green)',
                    bgColor: '#333',
                    isDeletable: true
                };
            }

            if (newItem) {
                // Check for duplicates by NAME OR PHONE (if both defined)
                // Bug fix: undefined === undefined returns true, so check existence first
                const isDuplicate = this.activeTab.items.some(item => {
                    if (!item) return false;
                    // Check by label
                    if (item.label === newItem!.label) return true;
                    // Check by phone (only if BOTH have phone defined)
                    const itemPhone = (item as any)?.phone;
                    const newPhone = data.phone;
                    if (itemPhone && newPhone && itemPhone === newPhone) return true;
                    return false;
                });
                if (isDuplicate) {
                    console.log('⚠️ Item already in favourite:', newItem.label);
                    this.duplicateModalMessage = `"${newItem.label}" already listed on this Favourite`;
                    this.showDuplicateModal = true;
                    return;
                }

                // Store phone in the item for future duplicate checks
                (newItem as any).phone = data.phone;

                // Add to slot
                this.activeTab.items[slotIndex] = newItem;
                this.tabs = [...this.tabs]; // Trigger change detection
                console.log(`✅ Added ${newItem.label} to favourite slot ${slotIndex}`);
            }
        } catch (e) {
            console.error('Favourite drop error:', e);
        }
    }

    // ============================================
    // FAVOURITE ITEM DRAG (For reordering filled items)
    // ============================================
    private draggedFavIndex: number | null = null;

    onFavItemDragStart(event: DragEvent, index: number): void {
        this.draggedFavIndex = index;
        const item = this.activeTab?.items[index];

        // Check if in edit mode
        const isEditMode = this.activeTab?.isEditMode || false;

        // Edit mode = reorder/delete within grid
        // Non-edit mode = copy to channel
        const dragType = isEditMode ? 'fav_item_reorder' : 'favourite_to_channel';

        if (event.dataTransfer && item) {
            event.dataTransfer.setData('application/json', JSON.stringify({
                type: dragType,
                sourceIndex: index,
                itemId: item.id,
                name: item.label,
                phone: (item as any).phone || item.id
            }));
            event.dataTransfer.effectAllowed = isEditMode ? 'move' : 'copy';
        }

        if (isEditMode) {
            (event.target as HTMLElement)?.classList.add('dragging');
        }
        console.log(`🔄 Fav item drag start (${dragType}):`, index, item?.label);
    }

    onFavItemDragOver(event: DragEvent, index: number): void {
        event.preventDefault();
        if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
        (event.target as HTMLElement)?.closest('.favourite-item')?.classList.add('drag-over');
    }

    onFavItemDrop(event: DragEvent, targetIndex: number): void {
        event.preventDefault();
        (event.target as HTMLElement)?.closest('.favourite-item')?.classList.remove('drag-over');
        document.querySelectorAll('.favourite-item.dragging').forEach(el => el.classList.remove('dragging'));

        if (!this.activeTab || this.draggedFavIndex === null || this.draggedFavIndex === targetIndex) {
            this.draggedFavIndex = null;
            return;
        }

        // SWAP items
        const sourceItem = this.activeTab.items[this.draggedFavIndex];
        const targetItem = this.activeTab.items[targetIndex];

        this.activeTab.items[targetIndex] = sourceItem;
        this.activeTab.items[this.draggedFavIndex] = targetItem;
        this.tabs = [...this.tabs]; // Trigger change detection

        console.log(`✅ Swapped favourite items: ${this.draggedFavIndex} <-> ${targetIndex}`);
        this.draggedFavIndex = null;
    }

    // ============================================
    // CHANNEL ACTION BAR DRAG
    // ============================================
    deleteSelected(): void {
        if (this.selectedChannel) {
            const index = this.channels.findIndex(c => c.key === this.selectedChannel!.key);
            if (index !== -1) {
                this.channels[index] = {
                    ...this.channels[index],
                    name: `Ch ${index + 1}`,
                    extension: '',
                    isActive: false,
                    groups: []
                };
                console.log('Deleted selected channel:', this.selectedChannel.key);
                this.selectedChannel = null;
            }
        }
    }

    onActionBtnDragOver(event: DragEvent, action: string): void {
        event.preventDefault();
        this.dragOverActionBtn = action;
    }

    onActionBtnDragLeave(event: DragEvent): void {
        this.dragOverActionBtn = null;
    }

    onActionBtnDrop(event: DragEvent, action: string): void {
        event.preventDefault();
        this.dragOverActionBtn = null;

        // Get channel from drag handle or dragged channel
        let channel: Channel | null = this.dragHandleChannel || this.draggedChannel;

        // Also check dataTransfer for channel-key
        if (!channel && event.dataTransfer) {
            const channelKey = event.dataTransfer.getData('channel-key');
            if (channelKey) {
                channel = this.channels.find(c => c.key === channelKey) || null;
            }
        }

        if (!channel) return;

        if (action === 'hangup') {
            console.log('📴 Hangup via drag:', channel.key);
            this.hangupChannel(channel);
        } else if (action === 'trash') {
            console.log('🗑️ Delete via drag:', channel.key);
            this.deleteChannel(channel);
        }

        this.draggedChannel = null;
        this.dragHandleChannel = null;
    }

    // ============================================
    // VIRTUAL KEYBOARD METHODS
    // ============================================

    @HostListener('document:click', ['$event'])
    @HostListener('document:touchstart', ['$event'])
    onDocumentClick(event: Event): void {
        if (!this.vkActive) return;
        const target = event.target as HTMLElement;

        // Check if click is inside keyboard or on the input field itself
        const isKeyboard = target.closest('.virtual-keyboard');
        const isInput = target === this.vkInput;

        if (!isKeyboard && !isInput) {
            this.hideKeyboard();
        }
    }

    showKeyboard(inputEl: HTMLInputElement): void {
        this.vkInput = inputEl;
        this.vkActive = true;
        this.vkSymbols = false;

        this.vkFirstKey = true;  // [FIX] Mark that next key should replace all

        // [FIX] Restore text selection after touch event (like SmartX)
        setTimeout(() => {
            if (this.vkInput) {
                this.vkInput.focus();
                this.vkInput.select();
            }
        }, 50);
    }

    hideKeyboard(): void {
        this.vkActive = false;
        this.vkInput = null;
        this.vkShift = false;
        this.vkSymbols = false;
    }

    // Done button - dispatch Enter key and hide keyboard
    vkDone(): void {
        if (this.vkInput) {
            // Dispatch Enter key event to trigger form submit
            const enterEvent = new KeyboardEvent('keydown', {
                key: 'Enter',
                code: 'Enter',
                keyCode: 13,
                which: 13,
                bubbles: true,
                cancelable: true
            });
            this.vkInput.dispatchEvent(enterEvent);

            // Also dispatch input event to ensure ngModel updates
            this.vkInput.dispatchEvent(new Event('input', { bubbles: true }));

            console.log('⌨️ VK Done - Enter dispatched');
        }
        this.hideKeyboard();
    }

    typeKey(char: string): void {
        if (this.vkInput) {
            const value = this.vkInput.value;

            // [FIX] On first key after VK opens, replace all text
            // This handles the case where touch deselects text before typeKey runs
            if (this.vkFirstKey && value.length > 0) {
                this.vkInput.value = char;
                this.vkInput.selectionStart = this.vkInput.selectionEnd = 1;
                this.vkFirstKey = false;
            } else {
                // Normal typing - use actual selection (handle 0 properly)
                const start = this.vkInput.selectionStart ?? value.length;
                const end = this.vkInput.selectionEnd ?? value.length;

                if (start !== end) {
                    // Text is selected - replace it
                    this.vkInput.value = value.substring(0, start) + char + value.substring(end);
                } else {
                    // No selection - insert at cursor
                    this.vkInput.value = value.substring(0, start) + char + value.substring(start);
                }
                this.vkInput.selectionStart = this.vkInput.selectionEnd = start + 1;
            }

            this.vkInput.focus();
            // Trigger input event for Angular binding
            this.vkInput.dispatchEvent(new Event('input'));
        }
    }

    backspace(): void {
        if (this.vkInput && this.vkInput.value.length > 0) {
            const start = this.vkInput.selectionStart || this.vkInput.value.length;
            const end = this.vkInput.selectionEnd || this.vkInput.value.length;
            const value = this.vkInput.value;
            if (start === end && start > 0) {
                // No selection, delete char before cursor
                this.vkInput.value = value.substring(0, start - 1) + value.substring(end);
                this.vkInput.selectionStart = this.vkInput.selectionEnd = start - 1;
            } else {
                // Selection, delete selected text
                this.vkInput.value = value.substring(0, start) + value.substring(end);
                this.vkInput.selectionStart = this.vkInput.selectionEnd = start;
            }
            this.vkInput.dispatchEvent(new Event('input'));
        }
    }

    toggleVkShift(): void {
        this.vkShift = !this.vkShift;
    }

    toggleVkSymbols(): void {
        this.vkSymbols = !this.vkSymbols;
    }

    // ============================================
    // LOGIN METHODS
    // ============================================
    processLogin(): void {
        this.loginStatus = 'Authenticating...';
        this.loginStatusColor = '#ffcc00';
        this.hideKeyboard();

        // Use Laravel API for authentication
        this.laravelAuth.login(this.loginUsername, this.loginPassword).subscribe({
            next: (result) => {
                if (result.success && result.extension) {
                    this.loginStatus = 'Connecting to PBX...';
                    console.log(`📞 Login as ${this.loginUsername} → Extension ${result.extension.extension}`);

                    // Store extension info
                    this.currentExtension = result.extension.extension;

                    // Register SIP with API-provided credentials
                    this.sipService.registerExtension({
                        server: result.extension.sip_server || '103.154.80.172',
                        port: 8089,
                        extension: result.extension.extension,
                        password: result.extension.secret || 'Maja1234'
                    });

                    // Wait for SIP registration
                    const sub = this.sipService.registrationStatus$.subscribe(status => {
                        if (status === 'registered') {
                            this.loginStatus = 'Connected!';
                            this.loginStatusColor = '#00ff66';
                            setTimeout(() => {
                                this.showLogin = false;
                                console.log('✅ SIP Registered, entered dashboard');
                            }, 500);
                            sub.unsubscribe();
                        } else if (status === 'failed') {
                            this.loginStatus = 'SIP Connection Failed';
                            this.loginStatusColor = '#ff4d4d';
                            sub.unsubscribe();
                        }
                    });

                    // Timeout fallback - enter anyway after 5s
                    setTimeout(() => {
                        if (this.showLogin) {
                            this.loginStatus = 'Entering (Offline Mode)...';
                            this.showLogin = false;
                            console.log('⚠️ SIP Registration timeout, entering offline mode');
                        }
                    }, 5000);
                } else {
                    // Login failed
                    this.loginStatus = result.error || 'Login Failed';
                    this.loginStatusColor = '#ff4d4d';
                    console.error('❌ Login failed:', result.error);
                }
            },
            error: (err) => {
                this.loginStatus = 'Authentication Error';
                this.loginStatusColor = '#ff4d4d';
                console.error('❌ Auth error:', err);
            }
        });
    }

    // === SIGN OUT ===
    signOut(): void {
        console.log('🚪 Signing out...');

        // Close any open drawers
        const offcanvases = document.querySelectorAll('.offcanvas.show');
        offcanvases.forEach(el => {
            const instance = bootstrap?.Offcanvas?.getInstance(el);
            if (instance) instance.hide();
        });

        // Disconnect SIP
        this.sipService.disconnect();

        // Clear auth token
        this.laravelAuth.logout();

        // Reset channels
        this.channels.forEach(ch => {
            ch.isActive = false;
            ch.isCalling = false;
            ch.name = '';
            ch.extension = '';
        });

        // Reset login form
        this.loginUsername = '';
        this.loginPassword = '';
        this.loginStatus = '';
        this.currentExtension = '';

        // Show login overlay and force UI update
        this.showLogin = true;
        this.cdr.detectChanges();

        console.log('✅ Signed out successfully');
    }

    // === AUDIO VOLUME CONTROL ===
    getChannelVolume(channelKey: string): number {
        return this.channelVolumes.get(channelKey) ?? 80; // Default 80%
    }

    setChannelVolume(channelKey: string, volume: number): void {
        const clampedVolume = Math.max(0, Math.min(100, Math.round(volume)));
        this.channelVolumes.set(channelKey, clampedVolume);
        // TODO: Apply to AudioContext gain node
        console.log(`🔊 Volume ${channelKey}: ${clampedVolume}%`);
    }

    onVolumeTouchStart(event: TouchEvent, channel: Channel): void {
        event.preventDefault();
        this.volumeDragChannel = channel;
        this.volumeDragStartY = event.touches[0].clientY;
        this.volumeDragStartValue = this.getChannelVolume(channel.key);
        console.log(`🎚️ Volume drag start: ${channel.key}`);
    }

    onVolumeTouchMove(event: TouchEvent, channel: Channel): void {
        if (!this.volumeDragChannel || this.volumeDragChannel.key !== channel.key) return;
        event.preventDefault();

        const deltaY = this.volumeDragStartY - event.touches[0].clientY; // Up = positive
        const deltaVolume = deltaY * 0.5; // 2px = 1%
        const newVolume = this.volumeDragStartValue + deltaVolume;
        this.setChannelVolume(channel.key, newVolume);
    }

    onVolumeTouchEnd(event: TouchEvent, channel: Channel): void {
        if (this.volumeDragChannel) {
            console.log(`🎚️ Volume drag end: ${channel.key} = ${this.getChannelVolume(channel.key)}%`);
        }
        this.volumeDragChannel = null;
    }

    onVolumeMouseDown(event: MouseEvent, channel: Channel): void {
        this.volumeDragChannel = channel;
        this.volumeDragStartY = event.clientY;
        this.volumeDragStartValue = this.getChannelVolume(channel.key);

        const onMouseMove = (e: MouseEvent) => {
            if (!this.volumeDragChannel) return;
            const deltaY = this.volumeDragStartY - e.clientY;
            const deltaVolume = deltaY * 0.5;
            const newVolume = this.volumeDragStartValue + deltaVolume;
            this.setChannelVolume(channel.key, newVolume);
        };

        const onMouseUp = () => {
            console.log(`🎚️ Volume drag end: ${channel.key} = ${this.getChannelVolume(channel.key)}%`);
            this.volumeDragChannel = null;
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        };

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    }

    // === AUDIO RECORDING (Mic Recording) ===
    loadRecordings(): void {
        const saved = localStorage.getItem('smartucx_recordings');
        if (saved) {
            this.recordings = JSON.parse(saved);
            console.log('📂 Loaded recordings:', this.recordings.length);
        }
    }

    saveRecordingsToStorage(): void {
        localStorage.setItem('smartucx_recordings', JSON.stringify(this.recordings));
        console.log('💾 Saved recordings to localStorage');
        // TODO: Also save to DB via API
    }

    async startMicRecording(): Promise<void> {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            this.mediaRecorder = new MediaRecorder(stream);
            this.recordingChunks = [];
            this.recordingStartTime = Date.now();
            this.isRecording = true;

            this.mediaRecorder.ondataavailable = (e) => {
                if (e.data.size > 0) {
                    this.recordingChunks.push(e.data);
                }
            };

            this.mediaRecorder.onstop = () => {
                stream.getTracks().forEach(track => track.stop());
            };

            this.mediaRecorder.start();
            console.log('🎙️ Recording started');
        } catch (err) {
            console.error('Failed to start recording:', err);
            alert('Microphone access denied!');
        }
    }

    stopMicRecording(): void {
        if (!this.mediaRecorder || !this.isRecording) return;

        this.mediaRecorder.stop();
        this.isRecording = false;

        // Wait for final data
        setTimeout(() => {
            const blob = new Blob(this.recordingChunks, { type: 'audio/webm' });
            const reader = new FileReader();
            reader.onloadend = () => {
                const duration = Math.round((Date.now() - this.recordingStartTime) / 1000);
                const name = this.currentRecordingName || `Recording ${this.recordings.length + 1}`;

                const recording: Recording = {
                    id: `rec-${Date.now()}`,
                    name: name,
                    duration: `${Math.floor(duration / 60)}:${(duration % 60).toString().padStart(2, '0')}`,
                    date: new Date().toLocaleDateString(),
                    filePath: reader.result as string
                };

                this.recordings.push(recording);
                this.saveRecordingsToStorage();
                this.currentRecordingName = '';
                console.log('🎙️ Recording saved:', recording.name);
            };
            reader.readAsDataURL(blob);
        }, 100);
    }

    deleteRecording(recordingId: string): void {
        const rec = this.getRecordingById(recordingId);
        if (!rec) return;

        this.pendingDeleteRecording = rec;
        this.showDeleteModal = true;
    }

    confirmDeleteRecording(): void {
        if (this.pendingDeleteRecording) {
            this.recordings = this.recordings.filter(r => r.id !== this.pendingDeleteRecording!.id);
            this.saveRecordingsToStorage();
            console.log('🗑️ Deleted recording:', this.pendingDeleteRecording.name);
        }
        this.pendingDeleteRecording = null;
        this.showDeleteModal = false;
    }

    onRecordingDragStart(event: DragEvent, rec: Recording): void {
        if (event.dataTransfer) {
            event.dataTransfer.setData('recording-id', rec.id);
            event.dataTransfer.effectAllowed = 'copy';
        }
        console.log('🎵 Drag recording:', rec.name);
    }

    assignRecordingToChannel(channelKey: string, recordingId: string): void {
        const channelIndex = this.channels.findIndex(c => c.key === channelKey);
        if (channelIndex !== -1) {
            const channel = this.channels[channelIndex];
            const currentRecordings = channel.channelRecordings || [];

            // Check max 3 recordings per channel
            if (currentRecordings.length >= 3) {
                this.duplicateModalMessage = `Channel already has 3 recordings assigned. Remove one first.`;
                this.showDuplicateModal = true;
                console.log(`❌ Channel ${channelKey} already has 3 audios`);
                return;
            }

            // Check if already assigned
            if (currentRecordings.some(r => r.id === recordingId)) {
                this.duplicateModalMessage = `This recording is already assigned to this channel.`;
                this.showDuplicateModal = true;
                console.log(`❌ Recording ${recordingId} already assigned to ${channelKey}`);
                return;
            }

            // Get next color from cycling array
            const color = this.AUDIO_COLORS[this.audioColorIndex % this.AUDIO_COLORS.length];
            this.audioColorIndex++;

            // Add recording to channel
            const newRecordings = [...currentRecordings, { id: recordingId, color }];
            const updatedChannel = { ...channel, channelRecordings: newRecordings };

            // Create new array with updated channel
            this.channels = [
                ...this.channels.slice(0, channelIndex),
                updatedChannel,
                ...this.channels.slice(channelIndex + 1)
            ];
            // Force change detection
            this.cdr.detectChanges();

            // Close the Audio Recording drawer
            const drawer = document.getElementById('audioRecordingDrawer');
            if (drawer) {
                const offcanvasInstance = bootstrap.Offcanvas.getInstance(drawer);
                if (offcanvasInstance) {
                    offcanvasInstance.hide();
                }
            }

            // Auto-switch to audiorec dashboard tab
            this.openPanel('recordings');

            console.log(`📎 Assigned recording ${recordingId} to ${channelKey} with color ${color} (${newRecordings.length}/3)`);
        }
    }

    removeRecordingFromChannel(channelKey: string, recordingId?: string): void {
        const channelIndex = this.channels.findIndex(c => c.key === channelKey);
        if (channelIndex !== -1) {
            const channel = this.channels[channelIndex];
            let newRecordings: ChannelRecording[] = [];

            if (recordingId) {
                // Remove specific recording
                newRecordings = (channel.channelRecordings || []).filter(r => r.id !== recordingId);
            }
            // else remove all recordings from channel

            const updatedChannel = { ...channel, channelRecordings: newRecordings.length > 0 ? newRecordings : undefined };
            this.channels = [
                ...this.channels.slice(0, channelIndex),
                updatedChannel,
                ...this.channels.slice(channelIndex + 1)
            ];
            this.cdr.detectChanges();
            console.log(`🗑️ Removed recording from ${channelKey}`);
        }
    }

    getRecordingById(recordingId: string): Recording | undefined {
        return this.recordings.find(r => r.id === recordingId);
    }

    playRecordingOnChannel(channelKey: string): void {
        const channel = this.channels.find(c => c.key === channelKey);
        if (!channel || !channel.channelRecordings?.length) return;

        // Play all recordings on this channel
        channel.channelRecordings.forEach(rec => {
            this.playRecording(rec.id);
        });
    }

    // Safe click handler for channel indicator slots
    playChannelRecordingAtIndex(channel: Channel, index: number): void {
        const rec = channel.channelRecordings?.[index];
        if (rec) {
            this.playRecording(rec.id);
        }
    }

    getChannelsWithRecordings(): Channel[] {
        return this.channels.filter(c => c.channelRecordings && c.channelRecordings.length > 0);
    }

    // Get recording by color (for legend tables)
    getRecordingByColor(color: string): Recording | undefined {
        for (const channel of this.channels) {
            const rec = channel.channelRecordings?.find(r => r.color === color);
            if (rec) {
                return this.getRecordingById(rec.id);
            }
        }
        return undefined;
    }

    // Get channel names that have this color recording (for legend tables)
    getChannelsByRecordingColor(color: string): string {
        const channelNames: string[] = [];
        for (const channel of this.channels) {
            if (channel.channelRecordings?.some(r => r.color === color)) {
                channelNames.push(`CH${channel.position}`);
            }
        }
        return channelNames.length > 0 ? channelNames.join(', ') : '';
    }

    // Get all unique recordings that are assigned to any channel, sorted by color order (red, yellow, blue)
    getActiveRecordings(): Recording[] {
        const recordingIds = new Set<string>();
        for (const channel of this.channels) {
            channel.channelRecordings?.forEach(r => recordingIds.add(r.id));
        }
        const activeRecs = this.recordings.filter(r => recordingIds.has(r.id));

        // Sort by color order: red → yellow → blue
        return activeRecs.sort((a, b) => {
            const colorA = this.getRecordingColor(a.id);
            const colorB = this.getRecordingColor(b.id);
            const orderA = this.AUDIO_COLORS.indexOf(colorA);
            const orderB = this.AUDIO_COLORS.indexOf(colorB);
            return (orderA === -1 ? 999 : orderA) - (orderB === -1 ? 999 : orderB);
        });
    }

    // Get color for a specific recording ID (grey if not assigned)
    getRecordingColor(recordingId: string): string {
        for (const channel of this.channels) {
            const rec = channel.channelRecordings?.find(r => r.id === recordingId);
            if (rec) return rec.color;
        }
        return '#888'; // grey = not assigned
    }

    // Check if a channel has a specific recording
    hasRecording(channel: Channel, recordingId: string): boolean {
        return channel.channelRecordings?.some(r => r.id === recordingId) || false;
    }

    // Start looping playback of all active recordings
    startPlayLoop(): void {
        const activeRecs = this.getActiveRecordings();
        if (activeRecs.length === 0) return;

        this.isPlayingLoop = true;
        this.loopAudioQueue = activeRecs.map(r => r.id);
        this.loopCurrentIndex = 0;
        this.playNextInLoop();
    }

    // Play next recording in the loop
    playNextInLoop(): void {
        if (!this.isPlayingLoop || this.loopAudioQueue.length === 0) return;

        const recordingId = this.loopAudioQueue[this.loopCurrentIndex];
        const recording = this.getRecordingById(recordingId);
        if (!recording || !recording.filePath) {
            this.loopCurrentIndex = (this.loopCurrentIndex + 1) % this.loopAudioQueue.length;
            this.playNextInLoop();
            return;
        }

        // Stop any currently playing audio
        if (this.currentAudio) {
            this.currentAudio.pause();
        }

        this.currentAudio = new Audio(recording.filePath);
        this.playingRecordingId = recordingId;

        // When audio ends, play next in loop
        this.currentAudio.onended = () => {
            if (this.isPlayingLoop) {
                this.loopCurrentIndex = (this.loopCurrentIndex + 1) % this.loopAudioQueue.length;
                this.playNextInLoop();
            }
        };

        this.currentAudio.play();
        console.log(`▶️ Loop playing: ${recording.name} (${this.loopCurrentIndex + 1}/${this.loopAudioQueue.length})`);
    }

    // Stop looping playback
    stopPlayLoop(): void {
        this.isPlayingLoop = false;
        if (this.currentAudio) {
            this.currentAudio.pause();
            this.currentAudio = null;
        }
        this.playingRecordingId = null;
        this.loopAudioQueue = [];
        this.loopCurrentIndex = 0;
        console.log('⏹️ Loop stopped');
    }

    // === SmartX-style Recording Panel Methods ===
    toggleRecording(): void {
        if (this.isRecording) {
            // Stop recording
            this.stopMicRecording();
            this.stopRecordingTimer();
            this.recordingComplete = true;
        } else {
            // Start recording
            this.recordingComplete = false;
            this.startMicRecording();
            this.startRecordingTimer();
        }
    }

    startRecordingTimer(): void {
        this.recordingTimer = '00:00';
        let seconds = 0;
        this.timerInterval = setInterval(() => {
            seconds++;
            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            this.recordingTimer = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        }, 1000);
    }

    stopRecordingTimer(): void {
        if (this.timerInterval) {
            clearInterval(this.timerInterval);
            this.timerInterval = null;
        }
    }

    playRecording(recordingId: string): void {
        // If clicking same recording that's playing, stop it
        if (this.playingRecordingId === recordingId && this.currentAudio) {
            this.currentAudio.pause();
            this.currentAudio = null;
            this.playingRecordingId = null;
            console.log('⏹️ Stopped recording:', recordingId);
            return;
        }

        // Stop any currently playing audio
        if (this.currentAudio) {
            this.currentAudio.pause();
            this.currentAudio = null;
        }

        const recording = this.getRecordingById(recordingId);
        if (!recording || !recording.filePath) {
            console.log('Recording not found or no file');
            return;
        }

        this.currentAudio = new Audio(recording.filePath);
        this.playingRecordingId = recordingId;

        // Reset state when audio ends
        this.currentAudio.onended = () => {
            this.playingRecordingId = null;
            this.currentAudio = null;
        };

        this.currentAudio.play();
        console.log('▶️ Playing recording:', recording.name);
    }

    editRecordingName(rec: Recording): void {
        this.editingRecording = rec;
        this.currentRecordingName = rec.name;
        // Focus the input, select text, and show VK after a tick
        setTimeout(() => {
            const input = document.getElementById('editRecordingNameInput') as HTMLInputElement;
            if (input) {
                input.focus();
                input.select();  // Auto-select all text for easy rename
                this.showKeyboard(input);  // [FIX] Use showKeyboard to set vkInput properly
            }
        }, 100);
        console.log('✏️ Editing recording:', rec.name);
    }

    saveEditedRecordingName(): void {
        if (this.editingRecording && this.currentRecordingName.trim()) {
            this.editingRecording.name = this.currentRecordingName.trim();
            this.saveRecordingsToStorage();
            console.log('✏️ Renamed recording to:', this.editingRecording.name);
        }
        this.editingRecording = null;
        this.currentRecordingName = '';
        this.hideVirtualKeyboard();
    }

    cancelEditRecordingName(): void {
        this.editingRecording = null;
        this.currentRecordingName = '';
        this.hideVirtualKeyboard();
    }

    saveRecordingWithName(): void {
        // Recording already captured by stopMicRecording, just reset UI
        this.recordingComplete = false;
        this.showRecordingPanel = false;
        this.recordingTimer = '00:00';
        console.log('💾 Recording saved with name:', this.currentRecordingName);
    }

    cancelRecording(): void {
        if (this.isRecording) {
            this.mediaRecorder?.stop();
            this.isRecording = false;
        }
        this.stopRecordingTimer();
        this.recordingComplete = false;
        this.showRecordingPanel = false;
        this.recordingTimer = '00:00';
        this.currentRecordingName = '';
        this.recordingChunks = [];
        console.log('❌ Recording cancelled');
    }
}

