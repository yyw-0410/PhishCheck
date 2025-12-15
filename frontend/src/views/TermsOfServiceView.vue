<script setup lang="ts">
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { ArrowLeft, FileText, Shield, Scale, AlertCircle, Lock, Mail, ExternalLink } from 'lucide-vue-next'
import { useRouter } from 'vue-router'
import { ref } from 'vue'

const router = useRouter()

const goBack = () => {
  router.back()
}

const sections = [
  { id: 'acceptance', title: '1. Acceptance of Terms', icon: Scale },
  { id: 'description', title: '2. Description of Service', icon: FileText },
  { id: 'responsibilities', title: '3. User Responsibilities', icon: Shield },
  { id: 'data-processing', title: '4. Data Processing', icon: Lock },
  { id: 'liability', title: '5. Limitation of Liability', icon: AlertCircle },
  { id: 'ip', title: '6. Intellectual Property', icon: FileText },
  { id: 'termination', title: '7. Account Termination', icon: AlertCircle },
  { id: 'changes', title: '8. Changes to Terms', icon: FileText },
  { id: 'contact', title: '9. Contact Information', icon: Mail },
]

const activeSection = ref('acceptance')

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
            <FileText class="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 class="text-3xl md:text-4xl font-bold tracking-tight mb-2">Terms of Service</h1>
            <p class="text-muted-foreground text-lg">Please read these terms carefully before using our service.</p>
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
              
              <section id="acceptance" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">1</span>
                  Acceptance of Terms
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed">
                    By accessing and using PhishCheck ("the Service"), you accept and agree to be bound by these Terms of Service. 
                    If you do not agree to these terms, please do not use the Service. These terms constitute a legally binding agreement between you and PhishCheck regarding your use of the Service.
                  </p>
                </div>
              </section>

              <Separator />

              <section id="description" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">2</span>
                  Description of Service
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed mb-4">
                    PhishCheck is an email security analysis platform that helps users identify potential phishing threats, 
                    analyze suspicious emails, and understand email authentication mechanisms. The Service includes:
                  </p>
                  <div class="grid sm:grid-cols-2 gap-4 not-prose">
                    <div class="p-4 rounded-lg border bg-card text-card-foreground shadow-sm">
                      <h3 class="font-medium mb-2 flex items-center gap-2">
                        <Mail class="h-4 w-4 text-primary" /> Email Analysis
                      </h3>
                      <p class="text-sm text-muted-foreground">Deep inspection of .eml files, headers, and body content.</p>
                    </div>
                    <div class="p-4 rounded-lg border bg-card text-card-foreground shadow-sm">
                      <h3 class="font-medium mb-2 flex items-center gap-2">
                        <Shield class="h-4 w-4 text-primary" /> Threat Intel
                      </h3>
                      <p class="text-sm text-muted-foreground">Integration with VirusTotal, Sublime Security, and more.</p>
                    </div>
                    <div class="p-4 rounded-lg border bg-card text-card-foreground shadow-sm">
                      <h3 class="font-medium mb-2 flex items-center gap-2">
                        <Lock class="h-4 w-4 text-primary" /> Authentication
                      </h3>
                      <p class="text-sm text-muted-foreground">Verification of SPF, DKIM, and DMARC records.</p>
                    </div>
                    <div class="p-4 rounded-lg border bg-card text-card-foreground shadow-sm">
                      <h3 class="font-medium mb-2 flex items-center gap-2">
                        <FileText class="h-4 w-4 text-primary" /> AI Assistance
                      </h3>
                      <p class="text-sm text-muted-foreground">Intelligent analysis and explanations powered by AI.</p>
                    </div>
                  </div>
                </div>
              </section>

              <Separator />

              <section id="responsibilities" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">3</span>
                  User Responsibilities
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed mb-4">You agree to use the Service responsibly and ethically. Specifically, you agree to:</p>
                  <ul class="space-y-2 list-none pl-0">
                    <li class="flex items-start gap-3">
                      <div class="h-6 w-6 rounded-full bg-green-500/10 flex items-center justify-center shrink-0 mt-0.5">
                        <div class="h-2 w-2 rounded-full bg-green-500"></div>
                      </div>
                      <span>Use the Service only for lawful purposes and security analysis.</span>
                    </li>
                    <li class="flex items-start gap-3">
                      <div class="h-6 w-6 rounded-full bg-green-500/10 flex items-center justify-center shrink-0 mt-0.5">
                        <div class="h-2 w-2 rounded-full bg-green-500"></div>
                      </div>
                      <span>Maintain the confidentiality of your account credentials.</span>
                    </li>
                    <li class="flex items-start gap-3">
                      <div class="h-6 w-6 rounded-full bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
                        <div class="h-2 w-2 rounded-full bg-red-500"></div>
                      </div>
                      <span>Not upload malicious content intended to harm the Service or other users.</span>
                    </li>
                    <li class="flex items-start gap-3">
                      <div class="h-6 w-6 rounded-full bg-red-500/10 flex items-center justify-center shrink-0 mt-0.5">
                        <div class="h-2 w-2 rounded-full bg-red-500"></div>
                      </div>
                      <span>Not attempt to reverse engineer or exploit the Service.</span>
                    </li>
                  </ul>
                </div>
              </section>

              <Separator />

              <section id="data-processing" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">4</span>
                  Data Processing
                </h2>
                <div class="prose prose-slate dark:prose-invert max-w-none text-muted-foreground">
                  <p class="leading-relaxed mb-4">
                    When you upload email files for analysis, the Service processes the content to identify potential threats. 
                    This includes extracting headers, URLs, IP addresses, and other metadata. 
                    Analysis data may be shared with third-party threat intelligence services including:
                  </p>
                  <div class="flex flex-wrap gap-2 not-prose">
                    <a href="https://www.virustotal.com" target="_blank" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted text-sm font-medium hover:bg-primary/20 hover:text-primary transition-colors">VirusTotal <ExternalLink class="h-3 w-3" /></a>
                    <a href="https://sublime.security" target="_blank" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted text-sm font-medium hover:bg-primary/20 hover:text-primary transition-colors">Sublime Security <ExternalLink class="h-3 w-3" /></a>
                    <a href="https://urlscan.io" target="_blank" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted text-sm font-medium hover:bg-primary/20 hover:text-primary transition-colors">URLScan.io <ExternalLink class="h-3 w-3" /></a>
                    <a href="https://www.ipqualityscore.com" target="_blank" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted text-sm font-medium hover:bg-primary/20 hover:text-primary transition-colors">IPQualityScore <ExternalLink class="h-3 w-3" /></a>
                    <a href="https://www.hybrid-analysis.com" target="_blank" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted text-sm font-medium hover:bg-primary/20 hover:text-primary transition-colors">Hybrid Analysis <ExternalLink class="h-3 w-3" /></a>
                    <a href="https://ai.google.dev" target="_blank" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-muted text-sm font-medium hover:bg-primary/20 hover:text-primary transition-colors">Google Gemini AI <ExternalLink class="h-3 w-3" /></a>
                  </div>
                </div>
              </section>

              <Separator />

              <section id="liability" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">5</span>
                  Limitation of Liability
                </h2>
                <div class="bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900 rounded-lg p-6 not-prose">
                  <div class="flex items-start gap-4">
                    <AlertCircle class="h-6 w-6 text-amber-600 dark:text-amber-500 shrink-0 mt-1" />
                    <div>
                      <h3 class="font-semibold text-amber-900 dark:text-amber-100 mb-2">Disclaimer</h3>
                      <p class="text-amber-800 dark:text-amber-200/80 text-sm leading-relaxed">
                        The Service is provided "as is" without warranties of any kind. PhishCheck does not guarantee 
                        100% detection of all phishing attempts or malicious content. Users should use the Service as 
                        one tool among many in their security practices and not rely solely on our analysis.
                      </p>
                    </div>
                  </div>
                </div>
              </section>

              <Separator />

              <section id="ip" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">6</span>
                  Intellectual Property
                </h2>
                <p class="text-muted-foreground leading-relaxed">
                  All content, features, and functionality of the Service are owned by PhishCheck and are protected 
                  by international copyright, trademark, and other intellectual property laws.
                </p>
              </section>

              <Separator />

              <section id="termination" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">7</span>
                  Account Termination
                </h2>
                <p class="text-muted-foreground leading-relaxed">
                  We reserve the right to suspend or terminate your access to the Service at any time for violation 
                  of these terms or for any other reason at our discretion.
                </p>
              </section>

              <Separator />

              <section id="changes" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">8</span>
                  Changes to Terms
                </h2>
                <p class="text-muted-foreground leading-relaxed">
                  We may update these Terms of Service from time to time. We will notify users of any material changes 
                  by posting the new terms on this page and updating the "Last updated" date.
                </p>
              </section>

              <Separator />

              <section id="contact" class="scroll-mt-20">
                <h2 class="text-2xl font-bold mb-4 flex items-center gap-3">
                  <span class="flex items-center justify-center h-8 w-8 rounded-lg bg-primary/10 text-primary text-sm">9</span>
                  Contact Information
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
            <Button variant="link" @click="router.push('/privacy')">
              Privacy Policy
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
