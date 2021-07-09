var trace1 = {
    x: ['JUN', 'JUL', 'AUG', 'SEP', 'OCT'],
    y: [1000, 2000, 2800, 2400, 2800],
    name: 'Products',
    type: 'bar'
  };
  
  var trace2 = {
    x: ['JUN', 'JUL', 'AUG', 'SEP', 'OCT'],
    y: [800, 1800, 2600, 2000, 2500],
    name: 'Sales',
    type: 'bar'
  };
  
  var data = [trace1, trace2];
  
  var layout = {barmode: 'group'};
  
  Plotly.newPlot('myDiv1', data, layout);
  