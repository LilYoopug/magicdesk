package io.github.mekhontsev.magicdesk;

import org.junit.Test;
import static org.junit.Assert.assertFalse;

public final class UiChoiceAdapterTest {
    @Test public void selectedAndPopupRowsShareAppearanceAndRetainTypedValues() throws Exception {
        RuntimeSourceFixture.verify("""
                static class Context { }
                static class View { boolean styled; UiColor background; }
                static class ViewGroup extends View { }
                enum UiColor { MUTED, PANEL, HOVER }
                static class R { static class layout { static int simple_spinner_item=1,simple_spinner_dropdown_item=2; } }
                static class ArrayAdapter<T> {
                    final List<T> values;
                    ArrayAdapter(Context c,int layout,List<T> values){this.values=values;}
                    void setDropDownViewResource(int value){}
                    T getItem(int i){return values.get(i);}
                    public View getView(int p,View convert,ViewGroup parent){return convert==null?new View():convert;}
                    public View getDropDownView(int p,View convert,ViewGroup parent){return getView(p,convert,parent);}
                }
                static class Spinner extends View {
                    final Context context=new Context(); Object popup,listener=new Object(); int selection=1;
                    ArrayAdapter<?> adapter;
                    Context getContext(){return context;}
                    void setPopupBackgroundDrawable(Object background){popup=background;}
                    void setAdapter(ArrayAdapter<?> value){adapter=value;}
                }
                static class UiToolLayout { static int dp(Context c,int dp){return dp;} }
                static class UiAppearance {
                    static void backgroundTint(View v,UiColor role){}
                    static Object paint(Context c,UiColor fill,int radius,UiColor border){return fill;}
                    static void contents(View v){v.styled=true;}
                    static void background(View v,UiColor role){v.background=role;}
                }
                """ + "static " + RuntimeSourceFixture.nestedClass("UiChoiceAdapter", "UiChoiceAdapter")
                    .replace("android.R.layout.", "R.layout.") + """
                public static void verify() {
                    var spinner=new Spinner();Object first=new Object(),second=new Object(),listener=spinner.listener;
                    UiChoiceAdapter.bind(spinner,new Object[]{first,second});
                    check(spinner.adapter.getItem(0)==first && spinner.adapter.getItem(1)==second,"typed values replaced by labels");
                    check(spinner.selection==1 && spinner.listener==listener,"styling replaced selection policy");
                    check(spinner.popup==UiColor.PANEL,"popup background retained platform palette");
                    var selected=spinner.adapter.getView(1,null,new ViewGroup());
                    var row=spinner.adapter.getDropDownView(1,null,new ViewGroup());
                    check(selected.styled && selected.background==null,"selected value needs host colors without a popup background");
                    check(row.styled && row.background==UiColor.PANEL,"late popup row missed appearance");
                    check(spinner.adapter.getDropDownView(0,row,new ViewGroup())==row,"row recycling lost");
                    UiChoiceAdapter.bind(spinner,List.of(first));
                    check(spinner.adapter.getItem(0)==first,"asynchronous catalog replacement lost values");
                }
                """);
    }

    @Test public void nativeSpinnerLayoutsBelongToTheSharedAdapter() throws Exception {
        try (var files=java.nio.file.Files.walk(java.nio.file.Path.of(RuntimeSourceFixture.MAIN))) {
            for (var file:files.filter(path->path.toString().endsWith(".java")).toList()) {
                if (file.getFileName().toString().equals("UiChoiceAdapter.java")) continue;
                assertFalse(file.toString(),java.nio.file.Files.readString(file).contains("simple_spinner_"));
            }
        }
    }
}
