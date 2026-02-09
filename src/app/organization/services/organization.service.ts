import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';

export interface Company {
    id?: number;
    name: string;
    code?: string;
    contact_person?: string;
    email?: string;
    phone?: string;
    address?: string;
    is_active: boolean;
    head_offices_count?: number;
    branches_count?: number;
}

export interface HeadOffice {
    id?: number;
    customer_id: number;
    name: string;
    code?: string;
    type: 'basic' | 'ha' | 'fo';
    country?: string;
    province?: string;
    city?: string;
    district?: string;
    address?: string;
    contact_name?: string;
    contact_phone?: string;
    description?: string;
    is_active: boolean;
    customer?: Company;
    branches_count?: number;
    call_servers_count?: number;
}

export interface Branch {
    id?: number;
    customer_id?: number;
    head_office_id?: number;
    call_server_id?: number;
    name: string;
    code?: string;
    country?: string;
    province?: string;
    city?: string;
    district?: string;
    address?: string;
    contact_name?: string;
    contact_phone?: string;
    description?: string;
    is_active: boolean;
    customer?: Company;
    head_office?: HeadOffice;
}

export interface SubBranch {
    id?: number;
    customer_id?: number;
    branch_id?: number;
    name: string;
    code?: string;
    country?: string;
    province?: string;
    city?: string;
    district?: string;
    address?: string;
    contact_name?: string;
    contact_phone?: string;
    description?: string;
    is_active: boolean;
    customer?: Company;
    branch?: Branch;
}

export interface PaginatedResponse<T> {
    data: T[];
    current_page: number;
    last_page: number;
    per_page: number;
    total: number;
}

@Injectable({
    providedIn: 'root'
})
export class OrganizationService {
    private apiUrl = environment.apiUrl + '/v1';

    constructor(private http: HttpClient) { }

    // Companies
    getCompanies(params?: { search?: string; page?: number; per_page?: number }): Observable<PaginatedResponse<Company>> {
        let httpParams = new HttpParams();
        if (params?.search) httpParams = httpParams.set('search', params.search);
        if (params?.page) httpParams = httpParams.set('page', params.page.toString());
        if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
        return this.http.get<PaginatedResponse<Company>>(`${this.apiUrl}/companies`, { params: httpParams });
    }

    getCompany(id: number): Observable<Company> {
        return this.http.get<Company>(`${this.apiUrl}/companies/${id}`);
    }

    createCompany(company: Company): Observable<{ message: string; data: Company }> {
        return this.http.post<{ message: string; data: Company }>(`${this.apiUrl}/companies`, company);
    }

    updateCompany(id: number, company: Partial<Company>): Observable<{ message: string; data: Company }> {
        return this.http.put<{ message: string; data: Company }>(`${this.apiUrl}/companies/${id}`, company);
    }

    deleteCompany(id: number): Observable<{ message: string }> {
        return this.http.delete<{ message: string }>(`${this.apiUrl}/companies/${id}`);
    }

    // Head Offices
    getHeadOffices(params?: { search?: string; customer_id?: number; page?: number; per_page?: number }): Observable<PaginatedResponse<HeadOffice>> {
        let httpParams = new HttpParams();
        if (params?.search) httpParams = httpParams.set('search', params.search);
        if (params?.customer_id) httpParams = httpParams.set('customer_id', params.customer_id.toString());
        if (params?.page) httpParams = httpParams.set('page', params.page.toString());
        if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
        return this.http.get<PaginatedResponse<HeadOffice>>(`${this.apiUrl}/head-offices`, { params: httpParams });
    }

    getHeadOffice(id: number): Observable<HeadOffice> {
        return this.http.get<HeadOffice>(`${this.apiUrl}/head-offices/${id}`);
    }

    createHeadOffice(headOffice: HeadOffice): Observable<{ message: string; data: HeadOffice }> {
        return this.http.post<{ message: string; data: HeadOffice }>(`${this.apiUrl}/head-offices`, headOffice);
    }

    updateHeadOffice(id: number, headOffice: Partial<HeadOffice>): Observable<{ message: string; data: HeadOffice }> {
        return this.http.put<{ message: string; data: HeadOffice }>(`${this.apiUrl}/head-offices/${id}`, headOffice);
    }

    deleteHeadOffice(id: number): Observable<{ message: string }> {
        return this.http.delete<{ message: string }>(`${this.apiUrl}/head-offices/${id}`);
    }

    // Branches
    getBranches(params?: { search?: string; customer_id?: number; head_office_id?: number; page?: number; per_page?: number }): Observable<PaginatedResponse<Branch>> {
        let httpParams = new HttpParams();
        if (params?.search) httpParams = httpParams.set('search', params.search);
        if (params?.customer_id) httpParams = httpParams.set('customer_id', params.customer_id.toString());
        if (params?.head_office_id) httpParams = httpParams.set('head_office_id', params.head_office_id.toString());
        if (params?.page) httpParams = httpParams.set('page', params.page.toString());
        if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
        return this.http.get<PaginatedResponse<Branch>>(`${this.apiUrl}/branches`, { params: httpParams });
    }

    getBranch(id: number): Observable<Branch> {
        return this.http.get<Branch>(`${this.apiUrl}/branches/${id}`);
    }

    createBranch(branch: Branch): Observable<{ message: string; data: Branch }> {
        return this.http.post<{ message: string; data: Branch }>(`${this.apiUrl}/branches`, branch);
    }

    updateBranch(id: number, branch: Partial<Branch>): Observable<{ message: string; data: Branch }> {
        return this.http.put<{ message: string; data: Branch }>(`${this.apiUrl}/branches/${id}`, branch);
    }

    deleteBranch(id: number): Observable<{ message: string }> {
        return this.http.delete<{ message: string }>(`${this.apiUrl}/branches/${id}`);
    }

    // Sub Branches
    getSubBranches(params?: { search?: string; branch_id?: number; page?: number; per_page?: number }): Observable<PaginatedResponse<SubBranch>> {
        let httpParams = new HttpParams();
        if (params?.search) httpParams = httpParams.set('search', params.search);
        if (params?.branch_id) httpParams = httpParams.set('branch_id', params.branch_id.toString());
        if (params?.page) httpParams = httpParams.set('page', params.page.toString());
        if (params?.per_page) httpParams = httpParams.set('per_page', params.per_page.toString());
        return this.http.get<PaginatedResponse<SubBranch>>(`${this.apiUrl}/sub-branches`, { params: httpParams });
    }

    getSubBranch(id: number): Observable<SubBranch> {
        return this.http.get<SubBranch>(`${this.apiUrl}/sub-branches/${id}`);
    }

    createSubBranch(subBranch: SubBranch): Observable<{ message: string; data: SubBranch }> {
        return this.http.post<{ message: string; data: SubBranch }>(`${this.apiUrl}/sub-branches`, subBranch);
    }

    updateSubBranch(id: number, subBranch: Partial<SubBranch>): Observable<{ message: string; data: SubBranch }> {
        return this.http.put<{ message: string; data: SubBranch }>(`${this.apiUrl}/sub-branches/${id}`, subBranch);
    }

    deleteSubBranch(id: number): Observable<{ message: string }> {
        return this.http.delete<{ message: string }>(`${this.apiUrl}/sub-branches/${id}`);
    }
}
