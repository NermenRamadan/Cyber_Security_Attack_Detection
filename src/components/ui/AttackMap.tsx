import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// تأكدي من تحميل ملف الـ JSON ووضعه في فولدر public/world-110m.json ليعمل محلياً
const geoUrl = "/world-110m.json";

const CYBER_COORDINATES: Record<string, [number, number]> = {
  "US": [-100, 40],
  "EG": [31, 27],
  "CN": [105, 35],
  "RU": [100, 60],
  "DE": [10, 51],
  "BR": [-55, -10],
  "IN": [78, 20],
  "Unknown": [0, 0]
};

export function AttackMap({ attacks }: { attacks: any[] }) {
  const activeAttacks = attacks
    .filter(a => a.status !== "normal")
    .slice(0, 25)
    .map((attack, index) => {
      const country = attack.source_country || "Unknown";
      const coordinates = CYBER_COORDINATES[country] || [
        30 + (index * 4) % 40,
        20 + (index * 3) % 20
      ];
      return {
        id: attack.id || index,
        coordinates: coordinates,
        severity: attack.severity
      };
    });

  return (
    // استخدام الـ Card الجاهز عندك من فولدر ui مع إضافة class الـ glass للتأثير الرقمي
    <Card className="glass relative overflow-hidden rounded-2xl lg:col-span-3 border-none">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <div>
          <CardTitle className="text-base font-semibold uppercase tracking-wider text-foreground">
            Live Cyber Threat Map
          </CardTitle>
          <CardDescription className="text-xs text-muted-foreground">
            Real-time incoming attack vectors by geographic source
          </CardDescription>
        </div>
        {activeAttacks.length > 0 && (
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
          </span>
        )}
      </CardHeader>
      
      <CardContent>
        <div className="h-80 w-full flex items-center justify-center bg-[#070a13]/80 rounded-xl overflow-hidden border border-white/5">
          <ComposableMap projectionConfig={{ scale: 140 }}>
            <Geographies geography={geoUrl}>
              {({ geographies }) =>
                 geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    style={{
                      default: { fill: "#111625", stroke: "#1e2638", strokeWidth: 0.6, outline: "none" },
                      hover: { fill: "#171e32", stroke: "#00f0ff", strokeWidth: 0.8, outline: "none" },
                      pressed: { fill: "#00f0ff", outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>
            
            {activeAttacks.map(({ id, coordinates, severity }) => {
              const isHigh = severity === "High" || severity === "Critical";
              return (
                <Marker key={id} coordinates={coordinates}>
                  <circle r={isHigh ? 9 : 6} fill={isHigh ? "#ef4444" : "#f59e0b"} className="animate-ping opacity-60" />
                  <circle r={isHigh ? 4 : 3} fill={isHigh ? "#ef4444" : "#f59e0b"} />
                </Marker>
              );
            })}
          </ComposableMap>
        </div>
      </CardContent>
    </Card>
  );
}