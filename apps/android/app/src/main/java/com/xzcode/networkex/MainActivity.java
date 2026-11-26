package com.xzcode.networkex;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.view.View;
import android.widget.*;
import org.json.*;
import mobile.Mobile;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native Android UI. All enrollment and file operations run off the UI thread. */
public final class MainActivity extends Activity {
    private static final int REQUEST_VPN=801;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private EditText server,name,invite,ca;
    private TextView status,peers,message;
    private Button enroll,connect,disconnect,forget;
    private CheckBox direct;
    private LinearLayout enrollment;
    private String root;
    private boolean busy;
    private final Runnable update=new Runnable(){@Override public void run(){refresh();handler.postDelayed(this,1500);}};
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        ScrollView scroll=new ScrollView(this);LinearLayout content=new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);content.setPadding(dp(20),dp(24),dp(20),dp(24));content.setBackgroundColor(Color.rgb(242,245,248));scroll.addView(content);setContentView(scroll);
        scroll.setOnApplyWindowInsetsListener((v,insets)->{v.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());return insets;});
        TextView title=text("Network EX",26);title.setTextColor(Color.rgb(36,49,66));content.addView(title);
        content.addView(text(getString(R.string.subtitle),14));
        enrollment=new LinearLayout(this);enrollment.setOrientation(LinearLayout.VERTICAL);content.addView(enrollment);
        server=field(enrollment,R.string.server,InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_URI);
        name=field(enrollment,R.string.device,InputType.TYPE_CLASS_TEXT);name.setText(Build.MODEL);
        invite=field(enrollment,R.string.invite,InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        ca=field(enrollment,R.string.ca,InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE);ca.setMinLines(2);
        enroll=button(enrollment,R.string.enroll);enroll.setOnClickListener(v->enroll());
        direct=new CheckBox(this);direct.setText(R.string.direct_experimental);
        direct.setChecked(getPreferences(MODE_PRIVATE).getBoolean("direct",false));content.addView(direct);
        direct.setOnCheckedChangeListener((b,checked)->getPreferences(MODE_PRIVATE).edit().putBoolean("direct",checked).apply());
        LinearLayout actions=new LinearLayout(this);actions.setOrientation(LinearLayout.HORIZONTAL);content.addView(actions);
        connect=button(actions,R.string.connect);disconnect=button(actions,R.string.disconnect);
        connect.setOnClickListener(v->prepareConnection());disconnect.setOnClickListener(v->stopService(new Intent(this,NetworkExVpnService.class)));
        content.addView(text(getString(R.string.status),18));status=text("",15);status.setTextIsSelectable(true);content.addView(status);
        content.addView(text(getString(R.string.peers),18));peers=text("",14);peers.setTextIsSelectable(true);content.addView(peers);
        message=text("",14);content.addView(message);
        forget=button(content,R.string.forget);forget.setOnClickListener(v->confirmForget());
        content.addView(text(getString(R.string.not_full_vpn),13));
        try{root=ProfileStore.root(this);}catch(Exception e){message.setText(e.getMessage());}
        refresh();
    }
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private TextView text(String value,int size){TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(Color.rgb(36,49,66));t.setPadding(0,dp(8),0,dp(8));return t;}
    private EditText field(LinearLayout layout,int hint,int type){EditText t=new EditText(this);t.setHint(hint);t.setInputType(type);t.setSingleLine((type&InputType.TYPE_TEXT_FLAG_MULTI_LINE)==0);t.setSaveEnabled(false);layout.addView(t,new LinearLayout.LayoutParams(-1,-2));return t;}
    private Button button(LinearLayout p,int label){Button b=new Button(this);b.setText(label);p.addView(b,new LinearLayout.LayoutParams(p.getOrientation()==LinearLayout.HORIZONTAL?0:-1,-2,p.getOrientation()==LinearLayout.HORIZONTAL?1:0));return b;}
    private void enroll(){
        if(root==null||busy||NetworkExVpnService.active())return;
        final String url=server.getText().toString().trim(),n=name.getText().toString().trim(),i=invite.getText().toString().trim(),c=ca.getText().toString().trim();
        invite.setText("");ca.setText("");busy=true;refresh();
        worker.execute(()->{String result;try{Mobile.enroll(root,url,n,i,c);result=getString(R.string.pending);}catch(Exception e){result=e.getMessage();}finishOperation(result);});
    }
    private void finishOperation(String text){runOnUiThread(()->{if(isDestroyed())return;busy=false;message.setText(text);refresh();});}
    private void prepareConnection(){
        if(root==null||busy||NetworkExVpnService.active())return;
        Intent request=VpnService.prepare(this);
        if(request!=null)startActivityForResult(request,REQUEST_VPN);else beginConnection();
    }
    @Override protected void onActivityResult(int code,int result,Intent data){super.onActivityResult(code,result,data);if(code==REQUEST_VPN){if(result==RESULT_OK)beginConnection();else message.setText(R.string.permission_denied);}}
    private void beginConnection(){
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},802);
        try{startForegroundService(new Intent(this,NetworkExVpnService.class).setAction(NetworkExVpnService.CONNECT).putExtra(NetworkExVpnService.DIRECT,direct.isChecked()));message.setText(R.string.session_wait);}catch(RuntimeException e){message.setText(e.getMessage());}
    }
    private void confirmForget(){
        if(busy||NetworkExVpnService.active()||root==null)return;
        new AlertDialog.Builder(this).setMessage(R.string.forget_confirm).setNegativeButton(R.string.cancel,null).setPositiveButton(R.string.ok,(d,w)->{
            busy=true;refresh();worker.execute(()->{String result;try{Mobile.forget(root);result=getString(R.string.no_profile);}catch(Exception e){result=e.getMessage();}finishOperation(result);});
        }).show();
    }
    private void refresh(){
        if(isDestroyed())return;
        boolean profile=root!=null&&Mobile.hasProfile(root),active=NetworkExVpnService.active();
        enrollment.setVisibility(profile?View.GONE:View.VISIBLE);
        enroll.setEnabled(root!=null&&!busy&&!active&&!profile);connect.setEnabled(profile&&!busy&&!active);disconnect.setEnabled(active);
        forget.setEnabled(root!=null&&!busy&&!active);direct.setEnabled(!active&&!busy);
        try{
            JSONObject s=new JSONObject(profile?NetworkExVpnService.status():"{}"),m=s.optJSONObject("managed"),t=s.optJSONObject("tunnel");
            StringBuilder out=new StringBuilder(profile?getString(R.string.profile_ready):getString(R.string.no_profile));
            if(m!=null){JSONObject d=m.optJSONObject("device");out.append("\n").append(m.optString("state"));if(d!=null)out.append("\n").append(d.optString("name")).append(" · ").append(d.optString("ip"));if(!m.optString("error").isEmpty())out.append("\n").append(m.optString("error"));}
            if(t!=null)out.append("\nVPN · ").append(t.optString("ip"));
            if(!s.optString("error").isEmpty())out.append("\n").append(s.optString("error"));
            status.setText(out.toString());
            StringBuilder list=new StringBuilder();JSONArray ps=m==null?null:m.optJSONArray("peers"),ts=t==null?null:t.optJSONArray("peers");
            if(ps!=null)for(int j=0;j<ps.length();j++){
                JSONObject p=ps.getJSONObject(j);String ip=p.optString("ip");list.append(p.optString("name")).append(" · ").append(ip);
                if(ts!=null)for(int k=0;k<ts.length();k++){JSONObject x=ts.getJSONObject(k);if(ip.equals(x.optString("ip")))list.append("\n  ").append(x.optString("mode")).append(" · RX ").append(x.optString("rx_bytes")).append(" B · TX ").append(x.optString("tx_bytes")).append(" B");}
                list.append("\n");
            }
            peers.setText(list.length()==0?"—":list.toString());
        }catch(Exception e){status.setText(e.getMessage());peers.setText("—");}
    }
    @Override protected void onResume(){super.onResume();handler.removeCallbacks(update);handler.post(update);}
    @Override protected void onPause(){handler.removeCallbacks(update);super.onPause();}
    @Override protected void onDestroy(){handler.removeCallbacks(update);worker.shutdown();super.onDestroy();}
}
