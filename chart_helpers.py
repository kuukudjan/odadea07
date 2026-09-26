"""
chart_helpers.py — reusable Chart.js snippets for reports and dashboards.
"""

import json


def bar_chart(canvas_id, labels, values, colors=None, height=280):
    if colors is None:
        colors = ['#1a3fbf'] * len(labels)
    return f"""
    <div style="position:relative;height:{height}px;">
      <canvas id="{canvas_id}"></canvas>
    </div>
    <script>
      (function(){{
        var ctx = document.getElementById({json.dumps(canvas_id)}).getContext('2d');
        new Chart(ctx, {{
          type: 'bar',
          data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
              label: 'Count',
              data: {json.dumps(values)},
              backgroundColor: {json.dumps(colors)},
              borderRadius: 6
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ y: {{ beginAtZero: true }} }}
          }}
        }});
      }})();
    </script>
    """


def line_chart(canvas_id, labels, values, height=280):
    return f"""
    <div style="position:relative;height:{height}px;">
      <canvas id="{canvas_id}"></canvas>
    </div>
    <script>
      (function(){{
        var ctx = document.getElementById({json.dumps(canvas_id)}).getContext('2d');
        new Chart(ctx, {{
          type: 'line',
          data: {{
            labels: {json.dumps(labels)},
            datasets: [{{
              label: 'Amount (GH₵)',
              data: {json.dumps(values)},
              borderColor: '#1a3fbf',
              backgroundColor: 'rgba(26,63,191,0.12)',
              fill: true,
              tension: 0.35,
              pointBackgroundColor: '#ed1c24',
              pointRadius: 4
            }}]
          }},
          options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ y: {{ beginAtZero: true }} }}
          }}
        }});
      }})();
    </script>
    """


CHART_JS_CDN = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>'