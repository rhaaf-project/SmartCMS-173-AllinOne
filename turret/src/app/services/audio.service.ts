// AudioService - Audio engine for visualizer, PTT, and playback
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { Capacitor } from '@capacitor/core';

export type AudioOutputMode = 'speaker' | 'earpiece';

export interface AudioDevice {
    deviceId: string;
    label: string;
    kind: 'audioinput' | 'audiooutput';
}

@Injectable({
    providedIn: 'root'
})
export class AudioService {
    private audioContext: AudioContext | null = null;
    private analysers = new Map<string, AnalyserNode>();
    private pttStream: MediaStream | null = null;
    private outputMode = new BehaviorSubject<AudioOutputMode>('speaker');

    // Audio device selection
    private inputDevices = new BehaviorSubject<AudioDevice[]>([]);
    private outputDevices = new BehaviorSubject<AudioDevice[]>([]);
    private selectedInputDeviceId = new BehaviorSubject<string>('default');
    private selectedOutputDeviceId = new BehaviorSubject<string>('default');

    public outputMode$ = this.outputMode.asObservable();
    public inputDevices$ = this.inputDevices.asObservable();
    public outputDevices$ = this.outputDevices.asObservable();
    public selectedInputDeviceId$ = this.selectedInputDeviceId.asObservable();
    public selectedOutputDeviceId$ = this.selectedOutputDeviceId.asObservable();

    constructor() {
        this.initAudioContext();
        this.detectAudioOutput();
        this.enumerateDevices();
    }

    /**
     * Initialize AudioContext
     */
    private initAudioContext(): void {
        this.audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
    }

    /**
     * Enumerate available audio devices (microphones & speakers)
     */
    async enumerateDevices(): Promise<void> {
        try {
            // Request permission first to get full device labels
            await navigator.mediaDevices.getUserMedia({ audio: true }).then(stream => {
                stream.getTracks().forEach(track => track.stop());
            }).catch(() => { });

            const devices = await navigator.mediaDevices.enumerateDevices();

            // Filter and clean up device list
            // Remove duplicates like "Default - xxx" and "Communications - xxx"
            const cleanDevices = (list: MediaDeviceInfo[], kind: 'audioinput' | 'audiooutput'): AudioDevice[] => {
                return list
                    .filter(d => d.kind === kind)
                    // Skip "Default -" and "Communications -" prefixed duplicates
                    .filter(d => !d.label.startsWith('Default - ') && !d.label.startsWith('Communications - '))
                    .map(d => ({
                        deviceId: d.deviceId,
                        label: d.label || `${kind === 'audioinput' ? 'Microphone' : 'Speaker'} ${d.deviceId.slice(0, 8)}`,
                        kind: kind
                    }));
            };

            const inputs = cleanDevices(devices, 'audioinput');
            const outputs = cleanDevices(devices, 'audiooutput');

            this.inputDevices.next(inputs);
            this.outputDevices.next(outputs);

            console.log('[Audio] Input devices:', inputs.length, 'Output devices:', outputs.length);

            // Auto-select USB headset if detected (for both input and output)
            this.autoSelectUsbHeadset(inputs, outputs);
        } catch (err) {
            console.error('[Audio] Failed to enumerate devices:', err);
        }
    }

    /**
     * Auto-select USB headset when connected
     */
    private autoSelectUsbHeadset(inputs: AudioDevice[], outputs: AudioDevice[]): void {
        // Look for USB headset keywords in device names
        const usbKeywords = ['usb', 'headset', 'headphone', 'lync', 'jabra', 'plantronics', 'logitech'];

        // Find USB input device
        const usbInput = inputs.find(d =>
            usbKeywords.some(keyword => d.label.toLowerCase().includes(keyword))
        );

        // Find USB output device
        const usbOutput = outputs.find(d =>
            usbKeywords.some(keyword => d.label.toLowerCase().includes(keyword))
        );

        // Auto-select if found and currently on default
        if (usbInput && this.selectedInputDeviceId.getValue() === 'default') {
            this.setInputDevice(usbInput.deviceId);
            console.log('[Audio] Auto-selected USB input:', usbInput.label);
        }

        if (usbOutput && this.selectedOutputDeviceId.getValue() === 'default') {
            this.setOutputDevice(usbOutput.deviceId);
            console.log('[Audio] Auto-selected USB output:', usbOutput.label);
        }
    }

    /**
     * Set selected input (microphone) device
     */
    setInputDevice(deviceId: string): void {
        this.selectedInputDeviceId.next(deviceId);
        console.log('[Audio] Selected input device:', deviceId);
    }

    /**
     * Set selected output (speaker) device
     */
    setOutputDevice(deviceId: string): void {
        this.selectedOutputDeviceId.next(deviceId);
        console.log('[Audio] Selected output device:', deviceId);
    }

    /**
     * Get current selected input device ID
     */
    getSelectedInputDeviceId(): string {
        return this.selectedInputDeviceId.getValue();
    }

    /**
     * Get current selected output device ID
     */
    getSelectedOutputDeviceId(): string {
        return this.selectedOutputDeviceId.getValue();
    }

    /**
     * Detect audio output mode (Speaker vs Earpiece) for mobile
     * This prevents audio distortion when phone is near ear
     */
    private async detectAudioOutput(): Promise<void> {
        if (Capacitor.isNativePlatform()) {
            // On mobile, we need to detect proximity sensor
            // This requires a Capacitor plugin for proximity detection
            // For now, default to speaker mode
            this.outputMode.next('speaker');

            // TODO: Implement proximity sensor detection
            // When proximity detected (phone near ear), switch to earpiece mode
            // This will be handled by a native plugin
        }
    }

    /**
     * Set audio output mode manually
     */
    setOutputMode(mode: AudioOutputMode): void {
        this.outputMode.next(mode);
        // Apply audio routing changes if on mobile
        if (Capacitor.isNativePlatform()) {
            this.applyAudioRouting(mode);
        }
    }

    /**
     * Apply audio routing for mobile (Speaker/Earpiece)
     */
    private applyAudioRouting(mode: AudioOutputMode): void {
        // This will be implemented via Capacitor native plugin
        // For web/Electron, this is a no-op
        console.log(`[Audio] Routing to: ${mode}`);
    }

    /**
     * Create analyser for ladder bar visualizer
     */
    createAnalyser(channelKey: string, stream: MediaStream): AnalyserNode | null {
        if (!this.audioContext) return null;

        const source = this.audioContext.createMediaStreamSource(stream);
        const analyser = this.audioContext.createAnalyser();

        analyser.fftSize = 256;
        analyser.smoothingTimeConstant = 0.8;

        source.connect(analyser);
        this.analysers.set(channelKey, analyser);

        return analyser;
    }

    /**
     * Get frequency data for visualizer (ladder bar)
     */
    getFrequencyData(channelKey: string): Uint8Array | null {
        const analyser = this.analysers.get(channelKey);
        if (!analyser) return null;

        const dataArray = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteFrequencyData(dataArray);

        return dataArray;
    }

    /**
     * Get volume level (0-100) for simple meter
     */
    getVolumeLevel(channelKey: string): number {
        const data = this.getFrequencyData(channelKey);
        if (!data) return 0;

        const sum = data.reduce((acc, val) => acc + val, 0);
        const avg = sum / data.length;
        return Math.min(100, Math.round(avg / 255 * 100));
    }

    /**
     * Start PTT (Push-to-Talk) audio capture
     */
    async startPtt(): Promise<MediaStream | null> {
        try {
            this.pttStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            });
            return this.pttStream;
        } catch (err) {
            console.error('[Audio] Failed to get microphone:', err);
            return null;
        }
    }

    /**
     * Stop PTT audio capture
     */
    stopPtt(): void {
        if (this.pttStream) {
            this.pttStream.getTracks().forEach(track => track.stop());
            this.pttStream = null;
        }
    }

    /**
     * Play audio file to SIP stream (audio injection)
     */
    async playToStream(audioUrl: string): Promise<AudioBufferSourceNode | null> {
        if (!this.audioContext) return null;

        try {
            const response = await fetch(audioUrl);
            const arrayBuffer = await response.arrayBuffer();
            const audioBuffer = await this.audioContext.decodeAudioData(arrayBuffer);

            const source = this.audioContext.createBufferSource();
            source.buffer = audioBuffer;
            source.connect(this.audioContext.destination);
            source.start(0);

            return source;
        } catch (err) {
            console.error('[Audio] Failed to play audio:', err);
            return null;
        }
    }

    /**
     * Resume AudioContext (required after user interaction)
     */
    async resumeContext(): Promise<void> {
        if (this.audioContext && this.audioContext.state === 'suspended') {
            await this.audioContext.resume();
        }
    }

    /**
     * Cleanup analyser for channel
     */
    removeAnalyser(channelKey: string): void {
        this.analysers.delete(channelKey);
    }

    /**
     * Cleanup all resources
     */
    destroy(): void {
        this.stopPtt();
        this.analysers.clear();
        if (this.audioContext) {
            this.audioContext.close();
            this.audioContext = null;
        }
    }

    // ============================================
    // AUDIO RECORDER
    // ============================================
    private mediaRecorder: MediaRecorder | null = null;
    private recordedChunks: Blob[] = [];
    private recordingStream: MediaStream | null = null;

    async startRecording(): Promise<void> {
        this.recordedChunks = [];
        try {
            this.recordingStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            });

            this.mediaRecorder = new MediaRecorder(this.recordingStream);

            this.mediaRecorder.ondataavailable = (event) => {
                if (event.data.size > 0) {
                    this.recordedChunks.push(event.data);
                }
            };

            this.mediaRecorder.start();
            console.log('[Audio] Recording started');
        } catch (err) {
            console.error('[Audio] Failed to start recording:', err);
            throw err;
        }
    }

    stopRecording(): Promise<Blob> {
        return new Promise((resolve, reject) => {
            if (!this.mediaRecorder || this.mediaRecorder.state === 'inactive') {
                return reject('Recorder not active');
            }

            this.mediaRecorder.onstop = () => {
                const blob = new Blob(this.recordedChunks, { type: 'audio/webm' });
                this.recordedChunks = [];

                // Stop all tracks
                if (this.recordingStream) {
                    this.recordingStream.getTracks().forEach(track => track.stop());
                    this.recordingStream = null;
                }

                this.mediaRecorder = null;
                resolve(blob);
            };

            this.mediaRecorder.stop();
            console.log('[Audio] Recording stopped');
        });
    }
}
