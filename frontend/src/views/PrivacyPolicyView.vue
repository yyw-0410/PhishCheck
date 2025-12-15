<script setup lang="ts">
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { 
  ArrowLeft, 
  Lock, 
  Info, 
  Database, 
  FileText, 
  Share2, 
  Clock, 
  Shield, 
  UserCheck, 
  Cookie, 
  Baby, 
  RefreshCw, 
  Mail,
  ExternalLink 
} from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { ref } from 'vue'

const router = useRouter()

const goBack = () => {
  router.back()
}

const sections = [
  { id: 'introduction', title: '1. Introduction', icon: Info },
  { id: 'collection', title: '2. Information We Collect', icon: Database },
  { id: 'usage', title: '3. How We Use Your Information', icon: FileText },
  { id: 'third-party', title: '4. Third-Party Services', icon: Share2 },
  { id: 'retention', title: '5. Data Retention', icon: Clock },
  { id: 'security', title: '6. Data Security', icon: Shield },
  { id: 'rights', title: '7. Your Rights', icon: UserCheck },
  { id: 'cookies', title: '8. Cookies and Tracking', icon: Cookie },
  { id: 'children', title: '9. Children\'s Privacy', icon: Baby },
  { id: 'changes', title: '10. Changes to Policy', icon: RefreshCw },
  { id: 'contact', title: '11. Contact Us', icon: Mail },
]

const activeSection = ref('introduction')

const scrollToSection = (id: string) => {
  const element = document.getElementById(id)
  if (element) {
    element.scrollIntoView({ behavior: 'smooth', block: 'start' })
    activeSection.value = id
  }
}
</script>

<template>
  <div class="min-h-screen bg-background">
    <!-- Back Button - Fixed Top Left -->
    <div class="fixed top-4 left-4 z-50">
      <Button variant="ghost" size="sm" class="text-muted-foreground hover:text-foreground" @click="goBack">
        <ArrowLeft class="h-4 w-4 mr-2" />
        Back
      </Button>
    </div>

    <!-- Header Hero -->
    <div class="bg-muted/30 border-b">
      <div class="container max-w-6xl mx-auto py-12 px-4 pt-16">
        <div class="flex flex-col md:flex-row md:items-center gap-6">
          <div class="h-16 w-16 rounded-2xl bg-primary/10 flex items-center justify-center shrink-0">
            <Lock class="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 class="text-3xl md:text-4xl font-bold tracking-tight mb-2">Privacy Policy</h1>
            <p class="text-muted-foreground text-lg">We are committed to protecting your privacy and personal data.</p>
            <div class="flex items-center gap-2 mt-4 text-sm text-muted-foreground">
              <span class="inline-block w-2 h-2 rounded-full bg-green-500"></span>
              Last updated: December 1, 2025
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="container max-w-6xl mx-auto py-12 px-4">
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-10">
        <!-- Sidebar Navigation -->
        <div class="hidden lg:block lg:col-span-3">
          <div class="sticky top-8 space-y-1">
            <p class="font-semibold mb-4 px-4">Table of Contents</p>
            <button
              v-for="section in sections"
              :key="section.id"
              @click="scrollToSection(section.id)"
              class="w-full text-left px-4 py-2 rounded-md text-sm transition-colors flex items-center gap-3"
              :class="activeSection === section.id 
                ? 'bg-primary/10 text-primary font-medium' 
                : 'text-muted-foreground hover:bg-muted hover:text-foreground'"
            >
              <component :is="section.icon" class="h-4 w-4" />
              <span class="truncate">{{ section.title }}</span>
            </button>
          </div>
        </div>

        <!-- Main Content -->
        <div class="lg:col-span-9 space-y-12">
          <Card class="border-none shadow-none bg-transparent">
            <CardContent class="p-0 space-y-12">
              
              <section id="introduction" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">1</span>
                  Introduction
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed">
                    PhishCheck ("we", "our", or "us") is committed to protecting your privacy. This Privacy Policy explains 
                    how we collect, use, disclose, and safeguard your information when you use our email security analysis service.
                  </p>
                </div>
              </section>

              <Separator />

              <section id="collection" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">2</span>
                  Information We Collect
                </h2>
                <div class="grid md:grid-cols-2 gap-6">
                  <div class="bg-card border rounded-lg p-5">
                    <h3 class="font-semibold mb-3 flex items-center gap-2">
                      <UserCheck class="h-4 w-4 text-primary" /> Account Information
                    </h3>
                    <ul class="space-y-2 text-sm text-muted-foreground">
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Email address
                      </li>
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Name (if provided)
                      </li>
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Profile picture (if using OAuth)
                      </li>
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Auth tokens from providers
                      </li>
                    </ul>
                  </div>
                  
                  <div class="bg-card border rounded-lg p-5">
                    <h3 class="font-semibold mb-3 flex items-center gap-2">
                      <Mail class="h-4 w-4 text-primary" /> Email Analysis Data
                    </h3>
                    <ul class="space-y-2 text-sm text-muted-foreground">
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Email headers & routing info
                      </li>
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Email body content
                      </li>
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        Attachments & metadata
                      </li>
                      <li class="flex items-start gap-2">
                        <span class="h-1.5 w-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        URLs & IP addresses
                      </li>
                    </ul>
                  </div>
                </div>
                
                <div class="mt-6 bg-muted/50 rounded-lg p-4">
                  <h3 class="font-semibold mb-2 text-sm">Usage Data</h3>
                  <p class="text-sm text-muted-foreground">
                    We automatically collect browser type, device info, IP address, pages visited, and timestamps to improve our service.
                  </p>
                </div>
              </section>

              <Separator />

              <section id="usage" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">3</span>
                  How We Use Your Information
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed mb-4">We use collected information to:</p>
                  <ul class="grid sm:grid-cols-2 gap-2 list-none pl-0">
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Provide email security analysis services
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Detect and identify phishing threats
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Improve threat detection algorithms
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Maintain and improve the Service
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Communicate about your account
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Respond to inquiries and support
                    </li>
                  </ul>
                </div>
              </section>

              <Separator />

              <section id="third-party" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">4</span>
                  Third-Party Services
                </h2>
                <p class="text-muted-foreground mb-6">
                  To provide comprehensive threat analysis, we share certain data with trusted third-party services:
                </p>
                <div class="grid sm:grid-cols-2 gap-4">
                  <a href="https://www.virustotal.com" target="_blank" class="p-4 bg-card border rounded-lg hover:shadow-md hover:border-primary/50 transition-all group">
                    <h4 class="font-semibold mb-1 flex items-center gap-1.5 group-hover:text-primary transition-colors">VirusTotal <ExternalLink class="h-3.5 w-3.5 opacity-50 group-hover:opacity-100" /></h4>
                    <p class="text-sm text-muted-foreground">URLs and file hashes are submitted for malware and reputation checking.</p>
                  </a>
                  <a href="https://sublime.security" target="_blank" class="p-4 bg-card border rounded-lg hover:shadow-md hover:border-primary/50 transition-all group">
                    <h4 class="font-semibold mb-1 flex items-center gap-1.5 group-hover:text-primary transition-colors">Sublime Security <ExternalLink class="h-3.5 w-3.5 opacity-50 group-hover:opacity-100" /></h4>
                    <p class="text-sm text-muted-foreground">Email content is analyzed for phishing patterns and threat indicators.</p>
                  </a>
                  <a href="https://urlscan.io" target="_blank" class="p-4 bg-card border rounded-lg hover:shadow-md hover:border-primary/50 transition-all group">
                    <h4 class="font-semibold mb-1 flex items-center gap-1.5 group-hover:text-primary transition-colors">URLScan.io <ExternalLink class="h-3.5 w-3.5 opacity-50 group-hover:opacity-100" /></h4>
                    <p class="text-sm text-muted-foreground">URLs are scanned to analyze website behavior and content.</p>
                  </a>
                  <a href="https://www.ipqualityscore.com" target="_blank" class="p-4 bg-card border rounded-lg hover:shadow-md hover:border-primary/50 transition-all group">
                    <h4 class="font-semibold mb-1 flex items-center gap-1.5 group-hover:text-primary transition-colors">IPQualityScore <ExternalLink class="h-3.5 w-3.5 opacity-50 group-hover:opacity-100" /></h4>
                    <p class="text-sm text-muted-foreground">IP addresses are checked for fraud and abuse history.</p>
                  </a>
                  <a href="https://www.hybrid-analysis.com" target="_blank" class="p-4 bg-card border rounded-lg hover:shadow-md hover:border-primary/50 transition-all group">
                    <h4 class="font-semibold mb-1 flex items-center gap-1.5 group-hover:text-primary transition-colors">Hybrid Analysis <ExternalLink class="h-3.5 w-3.5 opacity-50 group-hover:opacity-100" /></h4>
                    <p class="text-sm text-muted-foreground">File hashes are submitted to sandbox for malware behavior analysis.</p>
                  </a>
                  <a href="https://ai.google.dev" target="_blank" class="p-4 bg-card border rounded-lg hover:shadow-md hover:border-primary/50 transition-all group">
                    <h4 class="font-semibold mb-1 flex items-center gap-1.5 group-hover:text-primary transition-colors">Google Gemini AI <ExternalLink class="h-3.5 w-3.5 opacity-50 group-hover:opacity-100" /></h4>
                    <p class="text-sm text-muted-foreground">Analysis data may be processed by AI for intelligent threat assessment.</p>
                  </a>
                </div>
              </section>

              <Separator />

              <section id="retention" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">5</span>
                  Data Retention
                </h2>
                <div class="bg-muted/30 rounded-lg border p-6">
                  <div class="space-y-4">
                    <div class="flex justify-between items-center border-b pb-2">
                      <span class="font-medium">Account data</span>
                      <span class="text-sm text-muted-foreground">Until account deletion</span>
                    </div>
                    <div class="flex justify-between items-center border-b pb-2">
                      <span class="font-medium">Email analysis data</span>
                      <span class="text-sm text-muted-foreground">Temporary processing only</span>
                    </div>
                    <div class="flex justify-between items-center border-b pb-2">
                      <span class="font-medium">Chat conversations</span>
                      <span class="text-sm text-muted-foreground">Browser session only</span>
                    </div>
                    <div class="flex justify-between items-center">
                      <span class="font-medium">Usage logs</span>
                      <span class="text-sm text-muted-foreground">Up to 90 days</span>
                    </div>
                  </div>
                </div>
              </section>

              <Separator />

              <section id="security" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">6</span>
                  Data Security
                </h2>
                <div class="flex items-start gap-4 bg-green-50 dark:bg-green-950/20 p-6 rounded-lg border border-green-100 dark:border-green-900">
                  <Shield class="h-6 w-6 text-green-600 dark:text-green-500 shrink-0 mt-1" />
                  <div>
                    <h3 class="font-semibold text-green-900 dark:text-green-100 mb-2">Security Measures</h3>
                    <p class="text-green-800 dark:text-green-200/80 text-sm mb-4">
                      We implement appropriate security measures to protect your information.
                    </p>
                    <div class="grid sm:grid-cols-2 gap-x-8 gap-y-2 text-sm text-green-800 dark:text-green-200/80">
                      <div class="flex items-center gap-2">
                        <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
                        Encryption in transit (HTTPS/TLS)
                      </div>
                      <div class="flex items-center gap-2">
                        <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
                        Secure authentication
                      </div>
                      <div class="flex items-center gap-2">
                        <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
                        Regular security assessments
                      </div>
                      <div class="flex items-center gap-2">
                        <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
                        Access controls & audit logging
                      </div>
                    </div>
                  </div>
                </div>
              </section>

              <Separator />

              <section id="rights" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">7</span>
                  Your Rights
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed mb-4">You have the right to:</p>
                  <ul class="grid sm:grid-cols-2 gap-2 list-none pl-0">
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Access your personal data
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Correct inaccurate data
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Request deletion of your data
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Object to data processing
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Export your data
                    </li>
                    <li class="flex items-center gap-2">
                      <div class="h-1.5 w-1.5 rounded-full bg-primary"></div>
                      Withdraw consent at any time
                    </li>
                  </ul>
                </div>
              </section>

              <Separator />

              <section id="cookies" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">8</span>
                  Cookies and Tracking
                </h2>
                <p class="text-muted-foreground leading-relaxed">
                  We use essential cookies to maintain your session and preferences. We do not use third-party 
                  tracking cookies for advertising purposes. You can control cookie settings through your browser.
                </p>
              </section>

              <Separator />

              <section id="children" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">9</span>
                  Children's Privacy
                </h2>
                <p class="text-muted-foreground leading-relaxed">
                  The Service is not intended for children under 13 years of age. We do not knowingly collect 
                  personal information from children under 13.
                </p>
              </section>

              <Separator />

              <section id="changes" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">10</span>
                  Changes to This Policy
                </h2>
                <p class="text-muted-foreground leading-relaxed">
                  We may update this Privacy Policy from time to time. We will notify you of any changes by 
                  posting the new policy on this page and updating the "Last updated" date.
                </p>
              </section>

              <Separator />

              <section id="contact" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">11</span>
                  Contact Us
                </h2>
                <div class="bg-muted rounded-lg p-6 flex items-center gap-4">
                  <div class="h-12 w-12 rounded-full bg-background flex items-center justify-center shadow-sm">
                    <Mail class="h-6 w-6 text-primary" />
                  </div>
                  <div>
                    <p class="font-medium">Have questions?</p>
                    <p class="text-sm text-muted-foreground">Contact us through the Support section in the application.</p>
                  </div>
                </div>
              </section>

            </CardContent>
          </Card>

          <!-- Footer Links -->
          <div class="flex justify-center gap-6 pt-8 border-t">
            <Button variant="link" @click="router.push('/terms')">
              Terms of Service
            </Button>
            <Button variant="link" @click="router.push('/')">
              Back to Home
            </Button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.prose {
  max-width: none;
}
</style>
