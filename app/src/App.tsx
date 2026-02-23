import { useState, useEffect } from 'react'
import { 
  Shield, AlertTriangle, Users, Activity, 
  Clock, TrendingUp, 
  Bell, Menu, X,
  UserCheck, AlertOctagon, BarChart3, Eye, Download, Loader2, LogOut
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from '@/components/ui/table'
import { AuthProvider, useAuth } from '@/components/AuthContext'
import { LoginModal } from '@/components/LoginModal'
import { AlertDetailModal } from '@/components/AlertDetailModal'
import { UserProfileModal } from '@/components/UserProfileModal'
import { FilterDropdown } from '@/components/FilterDropdown'
import { mlAPI, dashboardAPI, alertsAPI, usersAPI, exportToCSV } from '@/lib/api'
import { RiskGauge } from '@/components/RiskGauge'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import './App.css'

// Types
interface AlertItem {
  id: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  user: string
  timestamp: string
  status: string
  risk_score: number
}

interface UserRisk {
  id: number
  username: string
  risk_score: number
  risk_level: string
  last_activity: string
  is_flagged: boolean
}

interface DashboardStats {
  total_users: number
  active_users: number
  flagged_users: number
  total_alerts: number
  critical_alerts: number
  high_risk_users: number
  avg_risk_score: number
}

// Main App Content (uses auth context)
function AppContent() {
  const { user, isAuthenticated, logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  const [loginModalOpen, setLoginModalOpen] = useState(false)
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null)
  const [alertModalOpen, setAlertModalOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<UserRisk | null>(null)
  const [userModalOpen, setUserModalOpen] = useState(false)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [isRetraining, setIsRetraining] = useState(false)
  const [selectedAlertTab, setSelectedAlertTab] = useState('all')
  const [isLoadingData, setIsLoadingData] = useState(false)
  const [showThreatAlert, setShowThreatAlert] = useState(false)

  const [stats, setStats] = useState<DashboardStats>({
    total_users: 5,
    active_users: 3,
    flagged_users: 1,
    total_alerts: 12,
    critical_alerts: 2,
    high_risk_users: 1,
    avg_risk_score: 32.5
  })

  // Demo alerts data
  const [alerts, setAlerts] = useState<AlertItem[]>([
    {
      id: 'ALT-20250205-7842',
      severity: 'critical',
      title: 'Potential Insider Threat Detected',
      user: 'malicious.user',
      timestamp: '2025-02-05 02:15:33',
      status: 'new',
      risk_score: 87.5
    },
    {
      id: 'ALT-20250205-7841',
      severity: 'high',
      title: 'After-Hours Sensitive File Access',
      user: 'john.doe',
      timestamp: '2025-02-05 01:30:12',
      status: 'acknowledged',
      risk_score: 72.3
    },
    {
      id: 'ALT-20250205-7840',
      severity: 'medium',
      title: 'Unusual Login Pattern',
      user: 'jane.smith',
      timestamp: '2025-02-04 22:45:00',
      status: 'investigating',
      risk_score: 45.8
    },
    {
      id: 'ALT-20250205-7839',
      severity: 'low',
      title: 'Failed Login Attempts',
      user: 'bob.wilson',
      timestamp: '2025-02-04 18:20:15',
      status: 'resolved',
      risk_score: 22.1
    }
  ])

  // Demo users at risk
  const [usersAtRisk, setUsersAtRisk] = useState<UserRisk[]>([
    {
      id: 5,
      username: 'malicious.user',
      risk_score: 87.5,
      risk_level: 'high',
      last_activity: '2025-02-05 02:15:33',
      is_flagged: true
    },
    {
      id: 1,
      username: 'john.doe',
      risk_score: 72.3,
      risk_level: 'high',
      last_activity: '2025-02-05 01:30:12',
      is_flagged: false
    },
    {
      id: 2,
      username: 'jane.smith',
      risk_score: 45.8,
      risk_level: 'medium',
      last_activity: '2025-02-04 22:45:00',
      is_flagged: false
    }
  ])

  // Activity feed
  const activityFeed = [
    { time: '02:15:33', user: 'malicious.user', action: 'Downloaded 50 sensitive files', severity: 'critical' },
    { time: '02:14:12', user: 'malicious.user', action: 'Data export attempt', severity: 'high' },
    { time: '02:10:05', user: 'malicious.user', action: 'Login from suspicious IP', severity: 'high' },
    { time: '01:30:12', user: 'john.doe', action: 'Accessed confidential document', severity: 'medium' },
    { time: '22:45:00', user: 'jane.smith', action: 'Login outside business hours', severity: 'low' },
    { time: '18:20:15', user: 'bob.wilson', action: 'Failed login attempt', severity: 'low' }
  ]

  // Fetch live data from API on mount
  useEffect(() => {
    const fetchData = async () => {
      setIsLoadingData(true)
      try {
        // Try to fetch from API
        const [dashboardData, alertsData, usersData] = await Promise.allSettled([
          dashboardAPI.getOverview(),
          alertsAPI.getAll(),
          usersAPI.getAll({ flagged: false })
        ])

        // Update stats if successful
        if (dashboardData.status === 'fulfilled' && dashboardData.value) {
          setStats(prev => ({
            ...prev,
            ...dashboardData.value
          }))
        }

        // Update alerts if successful
        if (alertsData.status === 'fulfilled' && alertsData.value?.alerts) {
          const apiAlerts = alertsData.value.alerts.map((a: any) => ({
            id: a.alert_id || a.id,
            severity: a.severity || 'medium',
            title: a.title || 'Unknown Alert',
            user: a.username || a.user || 'Unknown',
            timestamp: a.detected_at || a.timestamp || new Date().toISOString(),
            status: a.status || 'new',
            risk_score: a.risk_score || 0
          }))
          if (apiAlerts.length > 0) {
            setAlerts(apiAlerts)
          }
        }

        // Update users if successful
        if (usersData.status === 'fulfilled' && usersData.value?.users) {
          const apiUsers = usersData.value.users
            .filter((u: any) => u.risk_score > 25 || u.is_flagged)
            .map((u: any) => ({
              id: u.id,
              username: u.username,
              risk_score: u.risk_score || 0,
              risk_level: u.risk_level || (u.risk_score >= 75 ? 'high' : u.risk_score >= 50 ? 'medium' : 'low'),
              last_activity: u.last_login || u.last_activity || 'N/A',
              is_flagged: u.is_flagged || false
            }))
          if (apiUsers.length > 0) {
            setUsersAtRisk(apiUsers)
          }
        }
      } catch (err) {
        console.log('Using demo data - API not available')
      } finally {
        setIsLoadingData(false)
      }
    }

    fetchData()
  }, [])

  // Filtered alerts - consider both dropdown filters and tab selection
  const filteredAlerts = alerts.filter(alert => {
    // Tab filter (severity)
    if (selectedAlertTab !== 'all' && alert.severity !== selectedAlertTab) return false
    // Dropdown severity filter
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false
    // Status filter
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false
    return true
  })

  // Dynamic alert counts by severity
  const alertCounts = {
    all: alerts.length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    medium: alerts.filter(a => a.severity === 'medium').length,
    low: alerts.filter(a => a.severity === 'low').length
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white'
      case 'high': return 'bg-orange-500 text-white'
      case 'medium': return 'bg-yellow-500 text-black'
      case 'low': return 'bg-green-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500'
    if (score >= 50) return 'text-orange-500'
    if (score >= 25) return 'text-yellow-500'
    return 'text-green-500'
  }

  const getProgressColor = (score: number) => {
    if (score >= 75) return 'bg-red-600'
    if (score >= 50) return 'bg-orange-500'
    if (score >= 25) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  // Handle alert view
  const handleViewAlert = (alert: AlertItem) => {
    setSelectedAlert(alert)
    setAlertModalOpen(true)
  }

  // Handle alert acknowledge
  const handleAcknowledgeAlert = async (alertId: string) => {
    // Update local state optimistically
    setAlerts(prev => prev.map(a => 
      a.id === alertId ? { ...a, status: 'acknowledged' } : a
    ))
  }

  // Handle user view
  const handleViewUser = (user: UserRisk) => {
    setSelectedUser(user)
    setUserModalOpen(true)
  }

  // Handle user flag toggle
  const handleUserUpdate = () => {
    // Refresh users - toggle flag in local state
    if (selectedUser) {
      setUsersAtRisk(prev => prev.map(u =>
        u.id === selectedUser.id ? { ...u, is_flagged: !u.is_flagged } : u
      ))
    }
  }

  // Handle export to CSV
  const handleExport = () => {
    exportToCSV(filteredAlerts.map(a => ({
      'Alert ID': a.id,
      'Severity': a.severity,
      'Title': a.title,
      'User': a.user,
      'Risk Score': a.risk_score,
      'Status': a.status,
      'Timestamp': a.timestamp
    })), 'btis-alerts-export.csv')
  }

  // Handle retrain models
  const handleRetrainModels = async () => {
    setIsRetraining(true)
    try {
      await mlAPI.train()
      alert('Models retrained successfully!')
    } catch (err: any) {
      alert('Note: Backend not running. Models would be retrained when connected.')
    } finally {
      setIsRetraining(false)
    }
  }

  // Handle simulation
  const handleSimulateThreat = async () => {
    try {
      if (!confirm('Are you sure you want to simulate an insider threat? This will inject data and raise alerts.')) return
      
      const res = await fetch('http://localhost:5000/api/simulation/insider-threat', { method: 'POST' })
      const data = await res.json()
      
      if (data.success) {
        setShowThreatAlert(true) // Show overlay immediately
        alert('Simulation running! Watch the risk meter rise...')
        setTimeout(() => window.location.reload(), 2000) // Reload after 2s to show data
      } else {
        alert('Simulation failed: ' + data.error)
      }
    } catch (err) {
      alert('Failed to connect to backend simulation endpoint.')
    }
  }

  // Chart Data for visual comparison
  const chartData = [
    { name: 'Login Hour', baseline: 5, current: showThreatAlert ? 95 : 10 },
    { name: 'File Access', baseline: 15, current: showThreatAlert ? 88 : 18 },
    { name: 'Failed Login', baseline: 2, current: showThreatAlert ? 45 : 3 },
    { name: 'After Hours', baseline: 5, current: showThreatAlert ? 78 : 8 },
  ]

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Modals */}
      <LoginModal open={loginModalOpen} onOpenChange={setLoginModalOpen} />
      <AlertDetailModal 
        alert={selectedAlert} 
        open={alertModalOpen} 
        onOpenChange={setAlertModalOpen}
        onStatusChange={() => {
          if (selectedAlert) {
            handleAcknowledgeAlert(selectedAlert.id)
          }
        }}
      />
      <UserProfileModal
        user={selectedUser}
        open={userModalOpen}
        onOpenChange={setUserModalOpen}
        onUserUpdate={handleUserUpdate}
      />

      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-50">
        <div className="flex items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <Button 
              variant="ghost" 
              size="icon"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden"
            >
              {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-cyan-500" />
              <div>
                <h1 className="text-xl font-bold tracking-tight">BTIS</h1>
                <p className="text-xs text-slate-400">Behavioral Threat Intelligence System</p>
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <Button 
              variant="destructive" 
              className="hidden md:flex animate-pulse font-bold border-2 border-red-500 bg-red-950 text-red-100 hover:bg-red-900"
              onClick={handleSimulateThreat}
            >
              <AlertTriangle className="mr-2 h-4 w-4" />
              Simulate Threat
            </Button>

            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-slate-800 rounded-lg">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-sm text-slate-300">System Operational</span>
            </div>
            <Button variant="ghost" size="icon" className="relative">
              <Bell className="h-5 w-5" />
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-xs flex items-center justify-center">
                2
              </span>
            </Button>
            
            {/* User Avatar / Login */}
            {isAuthenticated ? (
              <div className="flex items-center gap-2">
                <div 
                  className="w-8 h-8 rounded-full bg-cyan-600 flex items-center justify-center cursor-pointer"
                  onClick={() => setLoginModalOpen(true)}
                >
                  <span className="text-sm font-medium">
                    {user?.username?.slice(0, 2).toUpperCase() || 'AD'}
                  </span>
                </div>
                <span className="hidden md:block text-sm">{user?.username || 'Admin'}</span>
                <Button variant="ghost" size="icon" onClick={logout}>
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            ) : (
              <Button 
                variant="outline" 
                size="sm"
                onClick={() => setLoginModalOpen(true)}
              >
                Login
              </Button>
            )}
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className={`${sidebarOpen ? 'w-64' : 'w-0'} transition-all duration-300 bg-slate-900 border-r border-slate-800 min-h-[calc(100vh-64px)] overflow-hidden`}>
          <nav className="p-4 space-y-2">
            <Button 
              variant={activeTab === 'overview' ? 'default' : 'ghost'} 
              className="w-full justify-start gap-3"
              onClick={() => setActiveTab('overview')}
            >
              <Activity className="h-4 w-4" />
              Overview
            </Button>
            <Button 
              variant={activeTab === 'alerts' ? 'default' : 'ghost'} 
              className="w-full justify-start gap-3"
              onClick={() => setActiveTab('alerts')}
            >
              <AlertTriangle className="h-4 w-4" />
              Alerts
              <Badge variant="destructive" className="ml-auto">2</Badge>
            </Button>
            <Button 
              variant={activeTab === 'users' ? 'default' : 'ghost'} 
              className="w-full justify-start gap-3"
              onClick={() => setActiveTab('users')}
            >
              <Users className="h-4 w-4" />
              Users at Risk
            </Button>
            <Button 
              variant={activeTab === 'behavior' ? 'default' : 'ghost'} 
              className="w-full justify-start gap-3"
              onClick={() => setActiveTab('behavior')}
            >
              <Eye className="h-4 w-4" />
              Behavior Analysis
            </Button>
            <Button 
              variant={activeTab === 'ml' ? 'default' : 'ghost'} 
              className="w-full justify-start gap-3"
              onClick={() => setActiveTab('ml')}
            >
              <BarChart3 className="h-4 w-4" />
              ML Models
            </Button>
          </nav>

          <div className="p-4 border-t border-slate-800">
            <div className="space-y-3">
              <p className="text-xs font-medium text-slate-400 uppercase">System Status</p>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">ML Engine</span>
                  <Badge variant="outline" className="text-green-500 border-green-500">Active</Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Risk Engine</span>
                  <Badge variant="outline" className="text-green-500 border-green-500">Active</Badge>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Alert System</span>
                  <Badge variant="outline" className="text-green-500 border-green-500">Active</Badge>
                </div>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 overflow-auto">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Page Title */}
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold">SOC Dashboard</h2>
                  <p className="text-slate-400">Real-time threat monitoring and behavioral analysis</p>
                </div>
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <Clock className="h-4 w-4" />
                  Last updated: {new Date().toLocaleTimeString()}
                </div>
              </div>

              {/* Critical Alert Banner */}
              <Alert className="bg-red-950/50 border-red-600/50">
                <AlertOctagon className="h-5 w-5 text-red-500" />
                <AlertTitle className="text-red-400">Critical Alert - Insider Threat Detected</AlertTitle>
                <AlertDescription className="text-red-300">
                  User <strong>malicious.user</strong> has triggered multiple high-risk behaviors. 
                  Immediate investigation recommended.
                </AlertDescription>
              </Alert>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-slate-400">Total Users</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div className="text-3xl font-bold">{stats.total_users}</div>
                      <Users className="h-8 w-8 text-cyan-500" />
                    </div>
                    <p className="text-xs text-slate-500 mt-1">{stats.active_users} currently active</p>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-slate-400">Active Alerts</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div className="text-3xl font-bold text-orange-500">{stats.total_alerts}</div>
                      <Bell className="h-8 w-8 text-orange-500" />
                    </div>
                    <p className="text-xs text-slate-500 mt-1">{stats.critical_alerts} critical</p>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-slate-400">Flagged Users</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div className="text-3xl font-bold text-red-500">{stats.flagged_users}</div>
                      <UserCheck className="h-8 w-8 text-red-500" />
                    </div>
                    <p className="text-xs text-slate-500 mt-1">Require immediate attention</p>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium text-slate-400">Avg Risk Score</CardTitle>
                  </CardHeader>
                  <CardContent className="flex justify-center pb-6">
                    <RiskGauge score={selectedUser ? selectedUser.risk_score : stats.avg_risk_score} size={160} />
                  </CardContent>
                </Card>
              </div>

              {/* Main Content Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Recent Alerts */}
                <Card className="lg:col-span-2 bg-slate-900 border-slate-800">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-orange-500" />
                        Recent Alerts
                      </CardTitle>
                      <Button variant="outline" size="sm" onClick={() => setActiveTab('alerts')}>
                        View All
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow className="border-slate-800">
                          <TableHead>Severity</TableHead>
                          <TableHead>Alert</TableHead>
                          <TableHead>User</TableHead>
                          <TableHead>Risk Score</TableHead>
                          <TableHead>Time</TableHead>
                          <TableHead>Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {alerts.map((alert) => (
                          <TableRow 
                            key={alert.id} 
                            className="border-slate-800 cursor-pointer hover:bg-slate-800/50"
                            onClick={() => handleViewAlert(alert)}
                          >
                            <TableCell>
                              <Badge className={getSeverityColor(alert.severity)}>
                                {alert.severity.toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-medium">{alert.title}</TableCell>
                            <TableCell>{alert.user}</TableCell>
                            <TableCell>
                              <span className={getRiskColor(alert.risk_score)}>
                                {alert.risk_score}
                              </span>
                            </TableCell>
                            <TableCell className="text-slate-400">{alert.timestamp}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className="capitalize">
                                {alert.status}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {/* Behavior Comparison Chart */}
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-cyan-500" />
                      Behavior Deviation
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-[300px] w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="name" stroke="#94a3b8" />
                          <YAxis stroke="#94a3b8" />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }}
                            itemStyle={{ color: '#e2e8f0' }}
                          />
                          <Legend />
                          <Bar dataKey="baseline" name="Baseline (Normal)" fill="#3b82f6" />
                          <Bar dataKey="current" name="Current Activity" fill={showThreatAlert ? "#ef4444" : "#22c55e"} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Users at Risk */}
              <Card className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2">
                      <Users className="h-5 w-5 text-red-500" />
                      Users at Risk
                    </CardTitle>
                    <Button variant="outline" size="sm" onClick={() => setActiveTab('users')}>
                      View All Users
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {usersAtRisk.map((user) => (
                      <div 
                        key={user.id} 
                        className={`p-4 rounded-lg border cursor-pointer hover:bg-slate-800/70 transition-colors ${
                          user.is_flagged ? 'bg-red-950/30 border-red-600/50' : 'bg-slate-800/50 border-slate-700'
                        }`}
                        onClick={() => handleViewUser(user)}
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <div className="w-10 h-10 rounded-full bg-slate-700 flex items-center justify-center">
                              <span className="text-sm font-medium">
                                {user.username.split('.').map(n => n[0]).join('').toUpperCase()}
                              </span>
                            </div>
                            <div>
                              <p className="font-medium">{user.username}</p>
                              {user.is_flagged && (
                                <Badge variant="destructive" className="text-xs">FLAGGED</Badge>
                              )}
                            </div>
                          </div>
                          <div className={`text-2xl font-bold ${getRiskColor(user.risk_score)}`}>
                            {user.risk_score}
                          </div>
                        </div>
                        <Progress 
                          value={user.risk_score} 
                          className={`h-2 ${getProgressColor(user.risk_score)}`}
                        />
                        <div className="flex items-center justify-between mt-3 text-xs text-slate-400">
                          <span>Risk Level: <span className="capitalize">{user.risk_level}</span></span>
                          <span>Last: {user.last_activity.split(' ')[1]}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'alerts' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold">Security Alerts</h2>
                  <p className="text-slate-400">Manage and respond to security alerts</p>
                </div>
                <div className="flex gap-2">
                  <FilterDropdown
                    severityFilter={severityFilter}
                    onSeverityChange={setSeverityFilter}
                    statusFilter={statusFilter}
                    onStatusChange={setStatusFilter}
                  />
                  <Button variant="outline" onClick={handleExport}>
                    <Download className="h-4 w-4 mr-2" />
                    Export
                  </Button>
                </div>
              </div>

              <Tabs defaultValue="all" className="w-full">
                <TabsList className="bg-slate-900 border border-slate-800">
                  <TabsTrigger value="all">All ({alerts.length})</TabsTrigger>
                  <TabsTrigger value="critical">Critical (2)</TabsTrigger>
                  <TabsTrigger value="high">High (3)</TabsTrigger>
                  <TabsTrigger value="medium">Medium (4)</TabsTrigger>
                  <TabsTrigger value="low">Low (3)</TabsTrigger>
                </TabsList>
                
                <TabsContent value="all" className="mt-4">
                  <Card className="bg-slate-900 border-slate-800">
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow className="border-slate-800">
                            <TableHead>Alert ID</TableHead>
                            <TableHead>Severity</TableHead>
                            <TableHead>Title</TableHead>
                            <TableHead>User</TableHead>
                            <TableHead>Risk Score</TableHead>
                            <TableHead>Detected</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredAlerts.map((alert) => (
                            <TableRow key={alert.id} className="border-slate-800">
                              <TableCell className="font-mono text-xs">{alert.id}</TableCell>
                              <TableCell>
                                <Badge className={getSeverityColor(alert.severity)}>
                                  {alert.severity.toUpperCase()}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-medium">{alert.title}</TableCell>
                              <TableCell>{alert.user}</TableCell>
                              <TableCell>
                                <span className={getRiskColor(alert.risk_score)}>
                                  {alert.risk_score}
                                </span>
                              </TableCell>
                              <TableCell className="text-slate-400">{alert.timestamp}</TableCell>
                              <TableCell>
                                <Badge variant="outline" className="capitalize">
                                  {alert.status}
                                </Badge>
                              </TableCell>
                              <TableCell>
                                <div className="flex gap-1">
                                  <Button 
                                    variant="ghost" 
                                    size="sm"
                                    onClick={() => handleViewAlert(alert)}
                                  >
                                    View
                                  </Button>
                                  <Button 
                                    variant="ghost" 
                                    size="sm"
                                    onClick={() => handleAcknowledgeAlert(alert.id)}
                                    disabled={alert.status === 'acknowledged' || alert.status === 'resolved'}
                                  >
                                    Ack
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </div>
          )}

          {activeTab === 'users' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold">Users at Risk</h2>
                  <p className="text-slate-400">Monitor users with elevated risk scores</p>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4">
                {usersAtRisk.map((user) => (
                  <Card key={user.id} className={`bg-slate-900 border-slate-800 ${
                    user.is_flagged ? 'border-red-600/50' : ''
                  }`}>
                    <CardContent className="p-6">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="w-16 h-16 rounded-full bg-slate-700 flex items-center justify-center">
                            <span className="text-xl font-medium">
                              {user.username.split('.').map(n => n[0]).join('').toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <h3 className="text-lg font-semibold">{user.username}</h3>
                              {user.is_flagged && (
                                <Badge variant="destructive">FLAGGED</Badge>
                              )}
                            </div>
                            <p className="text-sm text-slate-400">User ID: {user.id}</p>
                            <p className="text-sm text-slate-400">Last Activity: {user.last_activity}</p>
                          </div>
                        </div>
                        
                        <div className="text-right">
                          <div className={`text-4xl font-bold ${getRiskColor(user.risk_score)}`}>
                            {user.risk_score}
                          </div>
                          <p className="text-sm text-slate-400 capitalize">{user.risk_level} Risk</p>
                        </div>
                      </div>
                      
                      <div className="mt-4">
                        <div className="flex items-center justify-between text-sm mb-2">
                          <span className="text-slate-400">Risk Score</span>
                          <span className={getRiskColor(user.risk_score)}>{user.risk_score}/100</span>
                        </div>
                        <Progress 
                          value={user.risk_score} 
                          className={`h-3 ${getProgressColor(user.risk_score)}`}
                        />
                      </div>
                      
                      <div className="mt-4 flex gap-2">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleViewUser(user)}
                        >
                          View Profile
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleViewUser(user)}
                        >
                          Behavior Timeline
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm" 
                          className={user.is_flagged ? 'text-green-500' : 'text-red-500'}
                          onClick={() => {
                            setSelectedUser(user)
                            setUsersAtRisk(prev => prev.map(u =>
                              u.id === user.id ? { ...u, is_flagged: !u.is_flagged } : u
                            ))
                          }}
                        >
                          {user.is_flagged ? 'Unflag' : 'Flag User'}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'behavior' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold">Behavior Analysis</h2>
                  <p className="text-slate-400">AI-powered behavioral pattern analysis</p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle>Anomaly Detection</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="p-4 rounded-lg bg-slate-800/50">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium">Isolation Forest Model</span>
                          <Badge className="bg-green-600">Active</Badge>
                        </div>
                        <p className="text-sm text-slate-400">Primary anomaly detection algorithm</p>
                        <div className="mt-2 text-xs text-slate-500">
                          Contamination: 10% | Estimators: 100
                        </div>
                      </div>
                      
                      <div className="p-4 rounded-lg bg-slate-800/50">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium">User-Specific Models</span>
                          <Badge className="bg-green-600">5 Trained</Badge>
                        </div>
                        <p className="text-sm text-slate-400">Personalized models for each user</p>
                      </div>
                      
                      <div className="p-4 rounded-lg bg-slate-800/50">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-medium">Global Model</span>
                          <Badge className="bg-green-600">Trained</Badge>
                        </div>
                        <p className="text-sm text-slate-400">Organization-wide baseline model</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle>Behavior Features</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {[
                        'Login Hour Pattern',
                        'Session Duration',
                        'File Access Frequency',
                        'Command Usage',
                        'Failed Login Attempts',
                        'Sensitive Resource Access',
                        'Data Export Activity',
                        'Privilege Escalation',
                        'After-Hours Activity',
                        'Weekend Activity'
                      ].map((feature, idx) => (
                        <div key={idx} className="flex items-center gap-2 p-2 rounded bg-slate-800/50">
                          <div className="w-2 h-2 rounded-full bg-cyan-500" />
                          <span className="text-sm">{feature}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}

          {activeTab === 'ml' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold">ML Engine Status</h2>
                  <p className="text-slate-400">Machine learning model management</p>
                </div>
                <Button onClick={handleRetrainModels} disabled={isRetraining}>
                  {isRetraining ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Retraining...
                    </>
                  ) : (
                    'Retrain All Models'
                  )}
                </Button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="text-sm">Global Model</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Status</span>
                        <Badge className="bg-green-600">Active</Badge>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Algorithm</span>
                        <span>Isolation Forest</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Estimators</span>
                        <span>100</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Contamination</span>
                        <span>10%</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="text-sm">User Models</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Trained</span>
                        <span>5 / 5</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Pending</span>
                        <span>0</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Failed</span>
                        <span>0</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-900 border-slate-800">
                  <CardHeader>
                    <CardTitle className="text-sm">Performance</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Detection Rate</span>
                        <span>94.2%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">False Positive</span>
                        <span>3.8%</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Avg Latency</span>
                        <span>45ms</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </main>
      </div>
      {/* Threat Alert Overlay */}
      {showThreatAlert && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 animate-in fade-in duration-300">
          <div className="bg-slate-900 border-2 border-red-500 rounded-lg p-8 max-w-md w-full shadow-2xl shadow-red-500/50 animate-bounce-short">
            <div className="flex flex-col items-center text-center space-y-4">
              <div className="rounded-full bg-red-500/20 p-4 animate-pulse">
                <AlertTriangle className="h-16 w-16 text-red-500" />
              </div>
              <h2 className="text-3xl font-bold text-white tracking-widest uppercase">Insider Threat Detected</h2>
              <p className="text-red-200">High severity anomaly detected for user <span className="font-bold">malicious.user</span></p>
              
              <div className="grid grid-cols-2 gap-4 w-full mt-4">
                 <div className="bg-slate-800 p-3 rounded">
                   <div className="text-xs text-slate-400">Risk Score</div>
                   <div className="text-2xl font-bold text-red-500">92.5</div>
                 </div>
                 <div className="bg-slate-800 p-3 rounded">
                   <div className="text-xs text-slate-400">Anomalies</div>
                   <div className="text-2xl font-bold text-red-500">3</div>
                 </div>
              </div>

              <Button 
                className="w-full bg-red-600 hover:bg-red-700 text-white font-bold mt-4"
                onClick={() => setShowThreatAlert(false)}
              >
                ACKNOWLEDGE & INVESTIGATE
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Wrap with AuthProvider
function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}

export default App
