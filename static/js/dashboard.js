(() => {
  const d=window.dashboardData||{};
  if(typeof Chart==='undefined') return;
  Chart.defaults.color='#8697aa'; Chart.defaults.borderColor='#273544'; Chart.defaults.font.family='DM Sans';
  const activity=document.getElementById('activityChart');
  if(activity) new Chart(activity,{type:'line',data:{labels:(d.activity.labels||[]).map(x=>x.slice(5,16)),datasets:[{label:'Failed',data:d.activity.failed||[],borderColor:'#ff6475',backgroundColor:'#ff647520',fill:true,tension:.3},{label:'Successful',data:d.activity.success||[],borderColor:'#54d6a4',backgroundColor:'#54d6a420',fill:true,tension:.3}]},options:{maintainAspectRatio:false,plugins:{legend:{position:'bottom'}},scales:{x:{ticks:{maxTicksLimit:7},stacked:false},y:{beginAtZero:true,ticks:{precision:0}}}}});
  const sev=document.getElementById('severityChart');
  if(sev) new Chart(sev,{type:'doughnut',data:{labels:Object.keys(d.severity||{}),datasets:[{data:Object.values(d.severity||{}),backgroundColor:['#ff6475','#f6b95c','#74869a','#b39aff'],borderWidth:0}]},options:{maintainAspectRatio:false,plugins:{legend:{position:'bottom'}}}});
  const cat=document.getElementById('categoryChart');
  if(cat) new Chart(cat,{type:'bar',data:{labels:Object.keys(d.categories||{}),datasets:[{data:Object.values(d.categories||{}),backgroundColor:'#4bb9ce',borderRadius:4}]},options:{indexAxis:'y',maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{precision:0}}}}});
  const src=document.getElementById('sourceChart');
  if(src) new Chart(src,{type:'bar',data:{labels:Object.keys(d.tops||{}),datasets:[{label:'Alerts',data:Object.values(d.tops||{}),backgroundColor:'#8271dc',borderRadius:4}]},options:{indexAxis:'y',maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{precision:0}}}}});
})();
