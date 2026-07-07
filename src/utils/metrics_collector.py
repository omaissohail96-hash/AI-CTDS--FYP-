import time
from typing import Dict
from threading import Lock

class MetricsCollector:
    def __init__(self):
        self.lock = Lock()
        self.counters: Dict[str, int] = {
            "requests_total": 0,
            "cache_hits_total": 0,
            "cache_misses_total": 0,
            "false_positives_total": 0,
            "active_blocks": 0
        }
        self.histograms: Dict[str, list] = {
            "scan_duration_seconds": [],
            "risk_scores": []
        }

    def increment(self, name: str, value: int = 1):
        with self.lock:
            if name in self.counters:
                self.counters[name] += value
            else:
                self.counters[name] = value

    def observe(self, name: str, value: float):
        with self.lock:
            if name not in self.histograms:
                self.histograms[name] = []
            
            # Keep only last 1000 observations to avoid memory leak
            if len(self.histograms[name]) >= 1000:
                self.histograms[name].pop(0)
            self.histograms[name].append(value)

    def get_metrics(self) -> Dict:
        with self.lock:
            metrics = {
                "counters": dict(self.counters),
                "histograms": {}
            }
            
            # Calculate simple stats for histograms
            for name, values in self.histograms.items():
                if values:
                    metrics["histograms"][name] = {
                        "count": len(values),
                        "min": min(values),
                        "max": max(values),
                        "avg": sum(values) / len(values)
                    }
                else:
                    metrics["histograms"][name] = {"count": 0}
                    
            return metrics

    def generate_prometheus_format(self) -> str:
        lines = []
        with self.lock:
            for name, value in self.counters.items():
                lines.append(f"# TYPE cyberguard_{name} counter")
                lines.append(f"cyberguard_{name} {value}")
            
            for name, values in self.histograms.items():
                if values:
                    lines.append(f"# TYPE cyberguard_{name}_avg gauge")
                    lines.append(f"cyberguard_{name}_avg {sum(values)/len(values)}")
                    lines.append(f"# TYPE cyberguard_{name}_count counter")
                    lines.append(f"cyberguard_{name}_count {len(values)}")
                    
        return "\n".join(lines) + "\n"

# Singleton instance
metrics = MetricsCollector()
