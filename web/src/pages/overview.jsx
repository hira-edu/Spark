import React from 'react';
import { OverviewDashboard } from '../components/features/overview';

// DO NOT EDIT OR DELETE THIS COPYRIGHT MESSAGE.
console.log("%c By XZB %c https://github.com/XZB-1248/Rocket", 'font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;font-size:64px;color:#00bbee;-webkit-text-fill-color:#00bbee;-webkit-text-stroke:1px#00bbee;', 'font-size:12px;');

function overview(props) {
  return <OverviewDashboard />;
}

function wrapper(props) {
  let Component = overview;
  return (<Component {...props} key={Math.random()} />)
}

export default wrapper;
