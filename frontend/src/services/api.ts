/**
 * Centralized API configuration and utilities
 * Import API_BASE_URL from here instead of defining it in each file
 */

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

// Versioned API base URL (use this for all v1 API calls)
export const API_V1_URL = `${API_BASE_URL}/api/v1`

// Auth API URL (not versioned for backward compatibility)
export const API_AUTH_URL = `${API_BASE_URL}/api`

/**
 * Helper to build API endpoint URLs (v1)
 */
export function apiUrl(path: string): string {
    return `${API_V1_URL}${path.startsWith('/') ? path : '/' + path}`
}

/**
 * Common fetch wrapper with error handling
 */
export async function apiFetch<T>(
    path: string,
    options?: RequestInit
): Promise<T> {
    const response = await fetch(apiUrl(path), {
        ...options,
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...options?.headers,
        },
    })

    if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`API error ${response.status}: ${errorText}`)
    }

    return response.json()
}

/**
 * POST request helper
 */
export async function apiPost<T>(path: string, body: unknown): Promise<T> {
    return apiFetch<T>(path, {
        method: 'POST',
        body: JSON.stringify(body),
    })
}

/**
 * GET request helper
 */
export async function apiGet<T>(path: string): Promise<T> {
    return apiFetch<T>(path, { method: 'GET' })
}
