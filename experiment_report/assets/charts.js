// assets/charts.js — AgentLAB Experiment Report Charts
(function() {
  var style = getComputedStyle(document.documentElement);
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();
  var chartGrid = style.getPropertyValue('--chart-grid').trim() || rule;
  var chartAxis = style.getPropertyValue('--chart-axis').trim() || muted;
  var chartLabel = style.getPropertyValue('--chart-label').trim() || muted;
  var chartSeries = [
    style.getPropertyValue('--chart-series-1').trim(),
    style.getPropertyValue('--chart-series-2').trim(),
    style.getPropertyValue('--chart-series-3').trim(),
    style.getPropertyValue('--chart-series-4').trim()
  ];
  var chartOther = style.getPropertyValue('--chart-other').trim() || muted;

  // --- Chart: Attack Category Distribution ---
  var chart1 = echarts.init(document.getElementById('chart-category'), null, { renderer: 'svg' });
  chart1.setOption({
    animation: false,
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      appendToBody: true,
      backgroundColor: style.getPropertyValue('--chart-tooltip-bg').trim(),
      borderColor: rule,
      textStyle: { color: ink, fontSize: 13 }
    },
    grid: { left: 20, right: 40, top: 10, bottom: 0, containLabel: true },
    xAxis: {
      type: 'value',
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: chartAxis, fontSize: 12 },
      splitLine: { lineStyle: { color: chartGrid, type: 'dashed' } },
      max: 10
    },
    yAxis: {
      type: 'category',
      data: ['Data Leak', 'Email/Phishing', 'Credential Theft', 'Unauthorized Access', 'Malware/Exploit', 'Security Bypass', 'Other'],
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: chartAxis, fontSize: 12, width: 120, overflow: 'truncate' }
    },
    series: [{
      type: 'bar',
      data: [
        { value: 8, itemStyle: { color: chartSeries[0], borderRadius: [0, 4, 4, 0] } },
        { value: 6, itemStyle: { color: chartSeries[1], borderRadius: [0, 4, 4, 0] } },
        { value: 3, itemStyle: { color: chartSeries[2], borderRadius: [0, 4, 4, 0] } },
        { value: 2, itemStyle: { color: chartSeries[3], borderRadius: [0, 4, 4, 0] } },
        { value: 2, itemStyle: { color: chartSeries[0], borderRadius: [0, 4, 4, 0], opacity: 0.6 } },
        { value: 1, itemStyle: { color: chartOther, borderRadius: [0, 4, 4, 0] } },
        { value: 1, itemStyle: { color: chartOther, borderRadius: [0, 4, 4, 0], opacity: 0.6 } }
      ],
      barWidth: 20,
      label: {
        show: true,
        position: 'right',
        color: chartAxis,
        fontSize: 12,
        fontWeight: 600
      }
    }]
  });

  window.addEventListener('resize', function() { chart1.resize(); });
})();