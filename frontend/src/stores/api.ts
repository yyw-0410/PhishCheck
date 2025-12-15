import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import { API_BASE_URL } from '@/services/api'

export interface APIStatus {
    name: string
    status: 'live' | 'offline' | 'checking'
    lastChecked: Date | null
}

export const useAPIStore = defineStore('api', () => {
    const apiStatuses = ref<Record<string, APIStatus>>({
        virustotal: {
            name: 'VirusTotal API',
            status: 'checking',
            lastChecked: null
        },
        sublime: {
            name: 'Sublime API',
            status: 'checking',
            lastChecked: null
        },
        urlscan: {
            name: 'URLScan.io API',
            status: 'checking',
            lastChecked: null
        },
        ipqs: {
            name: 'IPQS API',
            status: 'checking',
            lastChecked: null
        },
        hybridanalysis: {
            name: 'Hybrid Analysis API',
            status: 'checking',
            lastChecked: null
        }
    })

    const checkAllAPIs = async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/api/v1/health/integrations`)

            if (response.ok) {
                const data = await response.json()
                const now = new Date()

                // Update each API status
                for (const [apiName, info] of Object.entries(data)) {
                    if (apiStatuses.value[apiName]) {
                        apiStatuses.value[apiName].status = (info as any).status
                        apiStatuses.value[apiName].lastChecked = now
                    }
                }
            }
        } catch (error) {
            console.error('Failed to check API status:', error)
            // Set all to offline on error
            const now = new Date()
            for (const api of Object.values(apiStatuses.value)) {
                api.status = 'offline'
                api.lastChecked = now
            }
        }
    }

    const checkAPIStatus = async (apiName: string) => {
        await checkAllAPIs()
    }

    const getAPIStatus = (apiName: string) => {
        return computed(() => apiStatuses.value[apiName])
    }

    const allAPIs = computed(() => Object.values(apiStatuses.value))

    return {
        apiStatuses,
        checkAPIStatus,
        checkAllAPIs,
        getAPIStatus,
        allAPIs
    }
})
