import { Component, AfterViewInit, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Router, RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { Store } from '@ngrx/store';
import { environment } from '../../../environments/environment';

interface Company {
    id: number;
    name: string;
    code: string;
}

// Import vis-network
declare var vis: any;

interface TopologyNode {
    id: string;
    label: string;
    title: string;
    group: 'headoffice' | 'branch' | 'standalone';
    status?: string;
    ip?: string;
    has_sbc?: boolean;
    branchCount?: number;
}

interface TopologyEdge {
    from: string;
    to: string;
    label: string;
    color: string;
}

interface TopologyData {
    nodes: TopologyNode[];
    edges: TopologyEdge[];
}

@Component({
    selector: 'app-connectivity-diagram',
    templateUrl: './connectivity-diagram.html',
    imports: [CommonModule, RouterModule, FormsModule],
})
export class ConnectivityDiagramComponent implements OnInit, AfterViewInit {
    store: any;
    topologyData: TopologyData = { nodes: [], edges: [] };
    isLoading = true;

    // Stats
    hoCount = 0;
    branchCount = 0;
    connectionCount = 0;

    // Company filter
    companies: Company[] = [];
    selectedCompanyId: string = '';

    private http = inject(HttpClient);
    private network: any = null;

    constructor(
        public storeData: Store<any>,
        public router: Router
    ) {
        this.initStore();
    }

    async initStore() {
        this.storeData
            .select((d) => d.index)
            .subscribe((d) => {
                this.store = d;
            });
    }

    ngOnInit() {
        this.loadTopologyData();
    }

    ngAfterViewInit() {
        // Load vis.js from CDN
        this.loadVisNetwork();
    }

    loadVisNetwork() {
        if (typeof vis !== 'undefined') {
            return;
        }

        const script = document.createElement('script');
        script.src = 'https://unpkg.com/vis-network/standalone/umd/vis-network.min.js';
        script.onload = () => {
            // vis.js loaded, re-render if data is ready
            if (this.topologyData.nodes.length > 0) {
                this.renderNetwork();
            }
        };
        document.head.appendChild(script);
    }

    loadTopologyData() {
        this.isLoading = true;
        let apiUrl = `${environment.apiUrl}/v1/topology`;

        // Add company filter if selected
        if (this.selectedCompanyId) {
            apiUrl += `?company_id=${this.selectedCompanyId}`;
        }

        this.http.get<any>(apiUrl).subscribe({
            next: (response) => {
                this.topologyData = response.data || { nodes: [], edges: [] };
                // Load companies from filter options
                if (response.filters?.companies) {
                    this.companies = response.filters.companies;
                }
                this.isLoading = false;
                // Use setTimeout to ensure DOM is ready
                setTimeout(() => {
                    this.renderNetwork();
                }, 100);
            },
            error: (error) => {
                console.error('Failed to load topology data:', error);
                this.isLoading = false;
            },
        });
    }

    onCompanyChange() {
        this.loadTopologyData();
    }

    renderNetwork() {
        if (typeof vis === 'undefined') {
            return;
        }

        const container = document.getElementById('topology-network');
        if (!container) {
            return;
        }

        // Count stats
        this.hoCount = 0;
        this.branchCount = 0;
        this.connectionCount = this.topologyData.edges.length;

        // Icon URLs - using assets folder
        const headOfficeIcon = 'assets/images/topology/head-office.png';
        const branchIcon = 'assets/images/topology/branch.png';
        const branchSbcIcon = 'assets/images/topology/branch-sbc.png';

        // Transform nodes for vis.js with proper icons
        const nodes = this.topologyData.nodes.map(node => {
            if (node.group === 'headoffice') {
                this.hoCount++;
                return {
                    id: node.id,
                    label: node.label + '\ntype: peer\nIP:',
                    title: node.title,
                    shape: 'image',
                    image: headOfficeIcon,
                    size: 45,
                    font: { color: '#374151', size: 11, face: 'arial', multi: true, align: 'left' }
                };
            } else if (node.group === 'standalone') {
                this.branchCount++;
                return {
                    id: node.id,
                    label: node.label + '\ntype: standalone\nIP: ' + (node.ip || 'N/A'),
                    title: node.title,
                    shape: 'image',
                    image: branchIcon,
                    size: 40,
                    font: { color: '#374151', size: 10, face: 'arial', multi: true }
                };
            } else {
                this.branchCount++;
                const isActive = node.status === 'OK';
                const hasSbc = node.has_sbc || false;
                return {
                    id: node.id,
                    label: node.label + '\ntype: peer\nIP: ' + (node.ip || 'N/A') + '\n' + (isActive ? 'OK' : 'Offline'),
                    title: node.title,
                    shape: 'image',
                    image: hasSbc ? branchSbcIcon : branchIcon,
                    size: 40,
                    font: { color: isActive ? '#16a34a' : '#dc2626', size: 10, face: 'arial', multi: true }
                };
            }
        });

        // Transform edges for vis.js
        const edges = this.topologyData.edges.map(edge => {
            return {
                from: edge.from,
                to: edge.to,
                label: edge.label,
                color: { color: edge.color, highlight: edge.color },
                width: 2,
                font: { color: edge.color, size: 14, strokeWidth: 0 },
                smooth: { type: 'curvedCW', roundness: 0.2 }
            };
        });

        // Create network
        const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };

        const options = {
            nodes: {
                borderWidth: 2,
                shadow: true
            },
            edges: {
                shadow: true,
                arrows: { to: { enabled: false } }
            },
            physics: {
                enabled: true,
                hierarchicalRepulsion: {
                    centralGravity: 0.0,
                    springLength: 200,
                    springConstant: 0.01,
                    nodeDistance: 80
                },
                solver: 'hierarchicalRepulsion'
            },
            layout: {
                hierarchical: {
                    enabled: true,
                    direction: 'LR',
                    sortMethod: 'directed',
                    levelSeparation: 200,
                    nodeSpacing: 50
                }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200
            }
        };

        this.network = new vis.Network(container, data, options);

        // Click handler - navigate to edit page
        this.network.on('click', (params: any) => {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                if (nodeId.startsWith('ho_')) {
                    const id = nodeId.replace('ho_', '');
                    this.router.navigate(['/admin/organization/head-office', id]);
                } else if (nodeId.startsWith('br_')) {
                    const id = nodeId.replace('br_', '');
                    this.router.navigate(['/admin/organization/branch', id]);
                }
            }
        });
    }

    refresh() {
        this.loadTopologyData();
    }
}
