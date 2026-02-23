import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'

interface RiskGaugeProps {
  score: number
  size?: number
}

export function RiskGauge({ score, size = 200 }: RiskGaugeProps) {
  // Data for the gauge
  const data = [
    { name: 'Score', value: score },
    { name: 'Remaining', value: 100 - score },
  ]

  // Determine color based on score
  const getColor = (value: number) => {
    if (value >= 75) return '#dc2626' // Red-600
    if (value >= 50) return '#f97316' // Orange-500
    if (value >= 25) return '#eab308' // Yellow-500
    return '#22c55e' // Green-500
  }

  const activeColor = getColor(score)
  const emptyColor = '#1e293b' // Slate-800

  // Needle rotation
  // 180 degrees total. 0 = left (-180deg), 100 = right (0deg) ???
  // Let's use standard half-donut. 
  // StartAngle 180 (left), EndAngle 0 (right)
  
  return (
    <div className="relative flex flex-col items-center justify-center p-4">
      <div className="relative" style={{ width: size, height: size / 2 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="100%"
              startAngle={180}
              endAngle={0}
              innerRadius="70%"
              outerRadius="100%"
              paddingAngle={0}
              dataKey="value"
              stroke="none"
            >
              <Cell key="score" fill={activeColor} />
              <Cell key="remaining" fill={emptyColor} />
            </Pie>
            <Tooltip content={<></>} />{/* Hide tooltip */}
          </PieChart>
        </ResponsiveContainer>
        
        {/* Score Display */}
        <div className="absolute inset-0 flex items-end justify-center pb-2 pointer-events-none">
          <div className="text-center">
            <span className="text-4xl font-bold text-slate-100">{Math.round(score)}</span>
            <span className="text-xs text-slate-400 block uppercase tracking-wider">Risk Score</span>
          </div>
        </div>
      </div>
      
      {/* Risk Level Badge */}
      <div className={`mt-4 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${
        score >= 75 ? 'bg-red-950 text-red-400 border border-red-800' :
        score >= 50 ? 'bg-orange-950 text-orange-400 border border-orange-800' :
        score >= 25 ? 'bg-yellow-950 text-yellow-400 border border-yellow-800' :
        'bg-green-950 text-green-400 border border-green-800'
      }`}>
        {score >= 75 ? 'Critical Risk' :
         score >= 50 ? 'High Risk' :
         score >= 25 ? 'Medium Risk' :
         'Normal'}
      </div>
    </div>
  )
}
