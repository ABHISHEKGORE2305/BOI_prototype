import { Info } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { shortFeatureName } from '../lib/format';

const RED = '#ff4d4d';
const CYAN = '#00d2ff';

export default function ShapChart({ shapData, features }) {
  const present = new Set(Object.values(features || {}).flat());

  const data = Object.entries(shapData || {})
    .map(([feature, value]) => ({
      feature,
      name: shortFeatureName(feature, 34),
      value: Number(value.toFixed(4)),
      present: present.has(feature),
    }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 10);

  return (
    <div className="nexus-card">
      <h3 className="card-title">
        <Info size={16} className="accent-cyan" aria-hidden="true" /> Why the model decided this (SHAP)
      </h3>
      <p className="card-caption">
        Red bars push towards malware, blue towards benign. Features marked “absent” contribute by
        <em> not </em> being present.
      </p>

      {data.length === 0 ? (
        <p className="muted">No attribution data.</p>
      ) : (
        <div className="chart-wrapper">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 5, right: 15, left: 15, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
              <XAxis type="number" stroke="#9ca3af" fontSize={10} tickLine={false} />
              <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={9} width={190} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0c0f17',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: '#fff',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
                cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                formatter={(value, _name, { payload }) => [
                  `${value > 0 ? '+' : ''}${value} (${payload.present ? 'present' : 'absent'})`,
                  payload.feature,
                ]}
                labelFormatter={() => ''}
              />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {data.map((entry) => (
                  <Cell key={entry.feature} fill={entry.value > 0 ? RED : CYAN} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
